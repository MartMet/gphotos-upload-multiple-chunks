
# gphotos-upload-multiple-chunks
Simple but flexible script to upload photos or videos to Google Photos. Useful if you have photos/videos in a directory structure that you want to reflect as Google Photos albums.

This fork provides file uploads in **multiple chunks** with **retrying behaviour** to prevent transmission errors and RAM exhaustion while uploading large items.

## Install
You need to install at least the following prerequisites:

* Python 3.7
* Python Magic 0.4.14        ```pip install python-magic-bin==0.4.14```
* Tenacity 6.0.0                    ```pip install tenacity==6.0.0```
* Glob2 0.7                           ```pip install glob2==0.7```

## Setup

### Obtaining a Google Photos API key

1. Obtain a Google Photos API key (Client ID and Client Secret) by following the instructions on [Getting started with Google Photos REST APIs](https://developers.google.com/photos/library/guides/get-started)

**NOTE** When selecting your application type in Step 4 of "Request an OAuth 2.0 client ID", please select "Other". There's also no need to carry out step 5 in that section.

2. Replace `YOUR_CLIENT_ID` in the client_id.json file with the provided Client ID. 
3. Replace `YOUR_CLIENT_SECRET` in the client_id.json file wiht the provided Client Secret.

 ## Usage 

```
usage: upload.py [-h] [--auth  auth_file] [--album album_name]
                 [--log log_file] [--glob_videos videos_dir]
                 [--glob_images images_dir] [--delete_files]
                 [item [item ...]]

Upload items (photo/video) to Google Photos.

positional arguments:
  item                  filename of a item to upload

optional arguments:
  -h, --help            show this help message and exit
  --auth  auth_file     file for reading/storing user authentication tokens
  --album album_name    name of album to create (if it doesn't exist). Any
                        uploaded item will be added to this album.
  --log log_file        name of output file for log messages
  --glob_videos videos_dir
                        search a provided directory recursively for video
                        files
  --glob_images images_dir
                        search a provided directory recursively for images
                        files
  --delete_files        switch to enable the deletion of files after
                        successfull upload
```

## Credits
forked from https://github.com/eshmu/gphotos-upload

