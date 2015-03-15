# File-Transfer
Application Level File Sharing Protocol with support for download and upload for files and indexed searching using tcp.
#### Compile : gcc file-name.c -lssl -lcrypto 
#### Run on terminal: ./a.out portno1 ip portno2
- IndexGet --shortlist start-time-stamp end-time-stamp : name, size, timestamp and type of the files between the start     and end time stamps.
- IndexGet --longlist : Entire listing of the shared folder/directory including name, size, timestamp and type of the      files.
- IndexGet --regex regex-argument : Similar to above, but with regular expression match. 
- FileHash --verify filename : Checksum and last-modified timestamp of the input file.
- FileHash --checkall : Filename, checksum and last-modified timestamp of all the files in the shared directory.
- FileDownload filename : Download file from server
- FileUpload filename : Upload file on server
- history : View terminal hostory 
