from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.credentials import Credentials
import json
import os.path
import argparse
import logging
import magic
from tenacity import retry, wait_fixed, stop_after_attempt
import glob2


def parse_args(arg_input=None):
    parser = argparse.ArgumentParser(description='Upload items (photo/video) to Google Photos.')
    parser.add_argument('--auth ', metavar='auth_file', dest='auth_file',
                        help='file for reading/storing user authentication tokens')
    parser.add_argument('--album', metavar='album_name', dest='album_name',
                        help='name of album to create (if it doesn\'t exist). Any uploaded item will be added to this album.')
    parser.add_argument('--log', metavar='log_file', dest='log_file',
                        help='name of output file for log messages')
    parser.add_argument('items', metavar='item', type=str, nargs='*',
                        help='filename of a item to upload')
    parser.add_argument('--glob_videos', metavar='videos_dir', dest='videos_dir',
                        help='search a provided directory recursively for video files')
    parser.add_argument('--glob_images', metavar='images_dir', dest='images_dir',
                        help='search a provided directory recursively for images files')
    parser.add_argument('--delete_files', dest='delete_files', action='store_true',
                        help='switch to enable the deletion of files after successfull upload')
    parser.set_defaults(delete_files=False)
    return parser.parse_args(arg_input)


def auth(scopes):
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_id.json',
        scopes=scopes)

    credentials = flow.run_local_server(host='localhost',
                                        port=8080,
                                        authorization_prompt_message="",
                                        success_message='The auth flow is complete; you may close this window.',
                                        open_browser=True)

    return credentials


def get_authorized_session(auth_token_file):
    scopes = ['https://www.googleapis.com/auth/photoslibrary',
              'https://www.googleapis.com/auth/photoslibrary.sharing']

    cred = None

    if auth_token_file:
        try:
            cred = Credentials.from_authorized_user_file(auth_token_file, scopes)
        except OSError as err:
            logging.debug("Error opening auth token file - {0}".format(err))
        except ValueError:
            logging.debug("Error loading auth tokens - Incorrect format")

    if not cred:
        cred = auth(scopes)

    session = AuthorizedSession(cred)

    if auth_token_file:
        try:
            save_cred(cred, auth_token_file)
        except OSError as err:
            logging.debug("Could not save auth tokens - {0}".format(err))

    return session


def save_cred(cred, auth_file):
    cred_dict = {
        'token': cred.token,
        'refresh_token': cred.refresh_token,
        'id_token': cred.id_token,
        'scopes': cred.scopes,
        'token_uri': cred.token_uri,
        'client_id': cred.client_id,
        'client_secret': cred.client_secret
    }

    with open(auth_file, 'w') as f:
        f.write(json.dumps(cred_dict))
        f.close()


# Generator to loop through all albums
def getAlbums(session, appCreatedOnly=False):
    params = {
        'excludeNonAppCreatedData': appCreatedOnly
    }

    while True:

        albums = session.get('https://photoslibrary.googleapis.com/v1/albums', params=params).json()

        logging.debug("Server response: {}".format(albums))

        if 'albums' in albums:

            for a in albums["albums"]:
                yield a

            if 'nextPageToken' in albums:
                params["pageToken"] = albums["nextPageToken"]
            else:
                return

        else:
            return


def create_or_retrieve_album(session, album_title):
    # Find albums created by this app to see if one matches album_title

    for a in getAlbums(session, True):
        if a["title"].lower() == album_title.lower():
            album_id = a["id"]
            logging.info("Uploading into EXISTING photo album -- \'{0}\'".format(album_title))
            return album_id

    # No matches, create new album
    create_album_body = json.dumps({"album": {"title": album_title}})
    # print(create_album_body)
    resp = post(session, 'https://photoslibrary.googleapis.com/v1/albums', create_album_body).json()

    logging.debug("Server response: {}".format(resp))

    if "id" in resp:
        logging.info("Uploading into NEW photo album -- \'{0}\'".format(album_title))
        return resp['id']
    else:
        logging.error("Could not find or create photo album '\{0}\'. Server Response: {1}".format(album_title, resp))
        return None


def upload_items(session, file_list, album_name, delete_file=False):
    album_id = create_or_retrieve_album(session, album_name) if album_name else None

    # interrupt upload if an upload was requested but could not be created
    if album_name and not album_id:
        return

    for file_name in file_list:
        upload_item(file_name, session, album_name, album_id, delete_file)


# retry uploading the whole item at least 6 times with one second wait time (tenacity)
# this function uses Google Photos Library API via the REST protocol (upload in multiple chunks)
# https://developers.google.com/photos/library/guides/resumable-uploads#multiple-chunks
@retry(reraise=True, wait=wait_fixed(1), stop=stop_after_attempt(6))
def upload_item(file_name, session, album_name, album_id, delete_file):
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_name)
    file_size = os.path.getsize(file_name)
    session.headers["Authorization"] = 'Bearer ' + session.credentials.token
    session.headers["Content-Length"] = "0"
    session.headers["X-Goog-Upload-Command"] = "start"
    session.headers["Content-type"] = mime_type
    session.headers["X-Goog-Upload-Protocol"] = "resumable"
    session.headers["X-Goog-Upload-File-Name"] = os.path.basename(file_name)
    session.headers["X-Goog-Upload-Raw-Size"] = str(file_size)

    upload_token = post(session, 'https://photoslibrary.googleapis.com/v1/uploads')
    try:
        del (session.headers["Authorization"])
        del (session.headers["Content-Length"])
        del (session.headers["X-Goog-Upload-Command"])
        del (session.headers["Content-type"])
        del (session.headers["X-Goog-Upload-Protocol"])
        del (session.headers["X-Goog-Upload-File-Name"])
        del (session.headers["X-Goog-Upload-Raw-Size"])
    except KeyError:
        pass
    if upload_token.status_code == 200:
        # response contains the desired granularity in bytes
        granularity = int(upload_token.headers["X-Goog-Upload-Chunk-Granularity"])
        upload_url = upload_token.headers["X-Goog-Upload-URL"]
        try:
            with open(file_name, mode='rb') as f:
                while True:
                    # read chunks of given granularity from file
                    f_bytes = f.read(granularity)
                    eof = False
                    # we reach EOF when the number of bytes we just read does not match the granularity
                    if len(f_bytes) != granularity:
                        eof = True
                    session.headers["Content-Length"] = str(len(f_bytes))
                    if not eof:
                        session.headers["X-Goog-Upload-Command"] = "upload"
                    else:
                        session.headers["X-Goog-Upload-Command"] = "upload, finalize"
                    # report the actual file offset
                    session.headers["X-Goog-Upload-Offset"] = str(f.tell() - len(f_bytes))
                    response = post(session, upload_url, f_bytes)

                    if response.status_code == 200:
                        logging.debug(str(f.tell()) + " bytes of " + str(file_size) + "bytes uploaded")
                    else:
                        logging.error(
                            "Could not upload \'{0}\'. Server Response -- {1}".format(
                                os.path.basename(file_name),
                                resp))
                        break
                    try:
                        del (session.headers["Content-Length"])
                        del (session.headers["X-Goog-Upload-Command"])
                        del (session.headers["X-Goog-Upload-Offset"])
                    except KeyError:
                        pass

                    if eof:
                        create_body = json.dumps({"albumId": album_id, "newMediaItems": [
                            {"description": "",
                             "simpleMediaItem": {"uploadToken": response.content.decode()}}]}, indent=4)
                        resp = post(session, 'https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate',
                                    create_body).json()

                        logging.debug("Server response: {}".format(resp))

                        if "newMediaItemResults" in resp:
                            status = resp["newMediaItemResults"][0]["status"]
                            if status.get("code") and (status.get("code") > 0):
                                logging.error(
                                    "Could not add \'{0}\' to library -- {1}".format(os.path.basename(file_name),
                                                                                     status["message"]))
                            else:
                                logging.info(
                                    "Added \'{}\' to library and album \'{}\' ".format(os.path.basename(file_name),
                                                                                       album_name))
                                if delete_file:
                                    os.remove(file_name)
                        else:
                            logging.error(
                                "Could not add \'{0}\' to library. Server Response -- {1}".format(
                                    os.path.basename(file_name),
                                    resp))

                        return
        except OSError as err:
            logging.error("Could not read file \'{0}\' -- {1}".format(file_name, err))


# simply wrap up the post function to engage retry functionality (tenacity)
# retry post for at least 6 times with 1 second wait time, reraise exception
@retry(reraise=True, wait=wait_fixed(1), stop=stop_after_attempt(6))
def post(session, url, f_bytes=None):
    response = session.post(url, f_bytes)
    return response


def main():
    args = parse_args()

    logging.basicConfig(format='%(asctime)s %(module)s.%(funcName)s:%(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I_%M_%S %p',
                        filename=args.log_file,
                        level=logging.INFO)

    session = get_authorized_session(args.auth_file)

    if not args.items:
        args.items = []

    if args.videos_dir:
        files = glob2.glob(args.videos_dir + "**/*.*", recursive=True)
        for file in files:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file)
            print(mime_type)
            if 'video' in mime_type:
                args.items.append(file)

    if args.images_dir:
        files = glob2.glob(args.images_dir + "**/*.*", recursive=True)
        for file in files:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file)
            if 'image' in mime_type:
                args.items.append(file)
    logging.debug("Files:  {}".format(args.items))
    upload_items(session, args.items, args.album_name, args.delete_files)

    # As a quick status check, dump the albums and their key attributes

    print("{:<50} | {:>8} | {} ".format("PHOTO ALBUM", "# ITEMS", "IS WRITEABLE?"))

    for a in getAlbums(session):
        print(
            "{:<50} | {:>8} | {} ".format(a["title"], a.get("mediaItemsCount", "0"), str(a.get("isWriteable", False))))


if __name__ == '__main__':
    main()
