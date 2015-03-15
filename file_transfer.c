#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <regex.h>
#include <time.h>
#include <errno.h>


typedef struct store_data{
	char filename[100]; 
	off_t size; 
	time_t mtime; 
	char type; 
	struct store_data *next;
}store_data;
store_data *indexget_data = NULL;

typedef struct store_hashing{
	char *filename; //filename
	unsigned char hash[MD5_DIGEST_LENGTH]; //hash
	time_t mtime; //last modified
	struct store_hashing *next;
} store_hashing;

struct store_hashing *hash_data = NULL;
int hist_count = 0;
char history[1024][1024] = {0};
char response[12048];
char errors[1024];
time_t prev_time;

struct store_hashing *cmp_data = NULL;

int main(int argc,char *argv[])
{
	if(argc != 4)
	{
		printf("Correct format :<listenportno> <ip of server> <connectportno> \n");
		return 1;
	} 
	char *listenportno = argv[1];
	char *connectportno = argv[3];
	char *ip = argv[2];
	pid_t pid;
	prev_time = time(NULL);
	pid = fork();
	if(pid == 0)
	{
		tcp_server(listenportno);
	}
	else if(pid > 0)
	{        
		tcp_client(ip,connectportno);
	}
	return 0;
}



int command(char input[] ){
	char cmd[1000];
	char *copy = NULL;
	strcpy(cmd, input);
	char command[100][100] ;
	command[0][0] = '\0';
	int i=0;
	copy = strtok(cmd, " ");

	while( copy != NULL ){
		strcpy(command[i],copy);
		int len = strlen(command[i]);
		if( command[i][len-1] == '\n')
			command[i][len-1] = '\0';
		i++;
		copy = strtok(NULL, " ");
	}

	command[i][0] = '\0'; 
	if( strcmp(command[0], "IndexGet" ) == 0 )
	{
		if( strcmp(command[1] , "--longlist") == 0 )
		{
			if( command[2][0] == '\0')
			{
				if( indexget(1,NULL,NULL) == 1 ) 
					return 1;   
			}
			else
			{
				sprintf(errors,"Invalid arguments\nShould be of type:\n\t--longlist\n");     
				return 0;			
			}
		}
		else if( strcmp(command[1] , "--shortlist") == 0 )
		{
			if( command[2] != NULL  && command[3] != NULL && command[4][0] == '\0')
			{
				if( indexget(2,command[2],command[3]) == 1 )
					return 2;
			}
			else
			{
				sprintf(errors,"Invalid arguments\nShould be of type:\n\t--shortlist<space>start-time-stamp<space>end-time-stamp\n");
				return 0;
			}
		}
		else if( strcmp(command[1] , "--regex") == 0 )
		{
			if( command[2] != NULL && command[3][0] == '\0')
			{
				if( indexget(3,command[2],NULL) == 1 ) 
					return 3;
			}   
			else
			{
				sprintf(errors,"Invalid arguments\nShould be of type:\n\t--regex<space><regular-expression>\n");
				return 0;
			}
		}
		else
		{
			sprintf(errors,"Invalid arguments\nShould be of type:\n\t--shortlist<space>start-time-stamp<space>end-time-stamp\n\t--longlist\n\t--regex<space><regular-expression>\n");
			return 0;
		}
	}
	else if( strcmp(command[0], "FileHash") == 0 )
	{
		if( strcmp(command[1] , "--verify") == 0 )
		{
			if( command[2] != NULL  && command[3][0] == '\0' && command[2][0] != '\0' )
			{
				if( filehash(2,command[2]) == 1 )
					return 4;
			}           
			else
			{
				sprintf(errors,"Invalid arguments\nShould be of type:\n\t--verify<space><filename>\n");
				return 0;
			}
		}           
		else if( strcmp(command[1] , "--checkall") == 0 )
		{
			if( command[2][0] == '\0')
			{
				if( filehash(1,NULL) == 1 )
					return 5;
			}
			else
			{
				sprintf(errors,"Invalid arguments\nShould be of type:\n\t--checkall\n");
				return 0;
			}
		}
		else
		{
			sprintf(errors,"Invalid arguments\nShould be of type:\n\t--verify<space><filename>\n\t--checkall\n");
			return 0;
		}
	}
	else if( strcmp(command[0], "FileDownload") == 0 )
	{
		if( command[1] != NULL  && command[2][0] == '\0')
		{
			return 6;
		}           
		else
		{
			sprintf(errors,"Invalid arguments\nShould be of type:\n\tFileDownload<space><filename>\n");
			return 0;
		}
	}
	else if( strcmp(command[0], "FileUpload") == 0 )
	{
		if( command[1] != NULL  && command[2][0] == '\0')
		{
			return 7;
		}           
		else
		{
			sprintf(errors,"Invalid arguments\nShould be of type:\n\tFileDownload<space><filename>\n");
			return 0;
		}
	}
	else if( strcmp(command[0] , "quit") == 0)
		return 12;

	else if( strcmp(command[0] , "history") == 0)
		return 13;


	else
	{
		sprintf(errors,"Random :to be handled :P\n");
		return 11;
	}
	return 0;
}

int indexget(int flag, char arg1[], char arg2[]){
	struct tm tm;
	time_t start, end;
	regex_t regex;
	int reti = 0;
	if( flag == 2 )
	{
		//		printf("flag is 2\n");
		if (strptime(arg1, "%d-%b-%Y-%H:%M:%S", &tm) == NULL)
		{
			sprintf(errors,"[SERVER]Invalid argument Should be of type :\n--shortlist<space>start_date-mon-yr-hr:min:sec<space>end_date-mon-yr-hr:min:sec\n");
			return 0 ;
		}
		start = mktime(&tm);
		if (strptime(arg2, "%d-%b-%Y-%H:%M:%S", &tm) == NULL)
		{
			sprintf(errors,"[SERVER]Invalid argument Should be of type :\n--shortlist<space>start_date-mon-yr-hr:min:sec<space>end_date-mon-yr-hr:min:sec\n");
			return 0;
		}
		end = mktime(&tm);
	}
	if(flag == 3 )
	{
		reti = regcomp(&regex, arg1, 0);
		if (reti) {
			sprintf(errors,"[SERVER]Could not compile regex\n");
			return 0;
		}
		//    regerror(reti, &regex, msgbuf, sizeof(msgbuf));
		//    sprintf(error,"Regex match failed: %s\n", msgbuf);    
		//  regfree(&regex);
	}

	DIR *dp;
	struct dirent *ep;
	dp = opendir ("./");
	struct stat file_stats;
	if (dp != NULL){
		while (ep = readdir (dp)){
			if(stat(ep->d_name,&file_stats) < 0)
				return 1;
			else if(!reti && (flag != 2 || ( flag == 2 &&(difftime(file_stats.st_mtime ,start ) > 0 && difftime(file_stats.st_mtime ,end ) <0) )))
			{
				//				printf("in else if\n");

				if( (flag == 3 && !(regexec(&regex, ep->d_name, 0, NULL, 0))) || flag != 3 )
				{
					store_data *node = (store_data *)malloc(sizeof(store_data));
					strcpy(node->filename, ep->d_name);
					node->size = file_stats.st_size;
					node->mtime = file_stats.st_mtime;
					if(S_ISDIR(file_stats.st_mode) == 'd' )
						node->type = 'd';
					else 
						node->type = '-';
					node->next = indexget_data;
					indexget_data = node;
				}
			}   
		}
		closedir (dp);
	}
	else
	{
		sprintf(errors,"[SERVER]Protected Folder! :");
		return 0;
	}   
	fflush(stdout);
	return 1;       
}


int filehash(int flag , char arg[])
{
	unsigned char c[MD5_DIGEST_LENGTH];
	DIR *dp;
	struct dirent *ep;
	dp = opendir ("./");
	struct stat file_stats;
	int bytes;
	unsigned char data[1024];

	int t =0;
	if( flag == 2)
		t= access(arg,F_OK);
	if (dp != NULL &&  t == 0)
	{
		while (ep = readdir (dp))
		{
			if(stat(ep->d_name,&file_stats) < 0)
				return 1;
			else if( flag == 1 || (flag == 2 && strcmp(arg,ep->d_name)==0))
			{
				FILE *fp = fopen (ep->d_name, "r"); 
				if (fp == NULL)
				{
					sprintf (errors,"Permissions denied : %s\n", ep->d_name);
					return 0;
				}          
				store_hashing *node = (store_hashing *)malloc(sizeof(store_hashing));
				node->filename = ep->d_name;
				node->mtime = file_stats.st_mtime;
				MD5_CTX mdctx;
				MD5_Init (&mdctx);
				while ((bytes = fread (data, 1, 1024, fp)) != 0)
					MD5_Update (&mdctx, data, bytes);
				MD5_Final (node->hash,&mdctx);
				/*  int var = 0;
				    while(var < MD5_DIGEST_LENGTH)
				    {
				    node->hash[var] = c[var];
				    var++;
				    }
				 */fclose (fp);
				node->next = hash_data;
				hash_data = node;
			}
		}
	}
	else if( dp == NULL )
	{
		sprintf(errors,"[SERVER]Couldn't open the folder");
		return 0;
	}
	else{
		sprintf(errors,"%s\n",strerror(errno));
		return 0;
	}
	return 1;
}

char prev_hashed[1000][1000];
char file_hashed[1000][1000];
int prev_len=0;

void checkhash( char str[] ){
	const char s[2] = "|";
	char *token;
	char copy[10000];
	char curr_hashed[1000][1000];
	char currf_hashed[1000][1000];
		
	strcpy(copy,str);

	int i=0,k,j;
	token = strtok(str, s);
	strcpy(curr_hashed[i],token);   
	token = strtok(NULL, s);
	strcpy(currf_hashed[i],token);
	token = strtok(NULL, s);
	i++;

	/* walk through other tokens */
	while( token != NULL ) 
	{
		strcpy(curr_hashed[i],token);   
		token = strtok(NULL, s);

		strcpy(currf_hashed[i],token);
		i++;
		token = strtok(NULL, s);
	}
	for(k=0;k<i;k++){
		for(j=0;j<prev_len;j++)
		{
			if( strcmp(curr_hashed[k], prev_hashed[j]) == 0 ){
				if( strcmp(currf_hashed[k], file_hashed[j]) != 0 )
				{
					printf("File changed: %s\n",curr_hashed[k]);
					strcpy(	file_hashed[j],currf_hashed[k]);			
				}
				break;
			}
		}
		if( j == prev_len )
		{
			printf("File added: %s\n",curr_hashed[k]);
			strcpy(	file_hashed[prev_len],currf_hashed[k]);		
			strcpy(	prev_hashed[prev_len],curr_hashed[k]);
			prev_len++;				
		}	
	}
}

int tcp_server(char *listenportno)
{
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr; 
	int portno = atoi(listenportno);
	int a , n , b , c;
	char readBuff[1024];
	char writeBuff[1024];

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd == -1)
	{
		perror("[SERVER]Unable to create socket");
		exit(0);
	}

	bzero(&serv_addr, sizeof(serv_addr));
	bzero(readBuff, sizeof(readBuff)); 
	bzero(writeBuff, sizeof(writeBuff)); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(portno); 

	if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
	{
		perror("Unable to bind");
		exit(0);
	}

	listen(listenfd, 10); 
	connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 

	n = read(connfd,readBuff,sizeof(readBuff));

	while( n > 0)
	{
		char request[1024];
		strcpy(request,readBuff);

		indexget_data = NULL;
		hash_data = NULL;
		response[0] = '\0';
		errors[0] ='\0';
		writeBuff[0] = '\0';

		strcpy(history[hist_count++],readBuff);

		int type_request = command(request);

		printf("\n>>> ");
		fflush(stdout);
		if( type_request == 12)
			break;

		if( type_request == 0 )      //Error
		{
			strcat(writeBuff,errors);
			strcat(writeBuff,"@@@");
			write(connfd , writeBuff , strlen(writeBuff));
			bzero(writeBuff, sizeof(writeBuff));
			bzero(readBuff, sizeof(readBuff)); 
			while((n = read(connfd,readBuff,sizeof(readBuff)))<=0);
			continue;
		}

		if(type_request == 11 )
		{
			strcat(writeBuff,"Message recieved: ");
			strcat(writeBuff,request);
			printf("%s\n",writeBuff);			
			bzero(writeBuff, sizeof(writeBuff));
			strcat(writeBuff,"@@@");
			write(connfd , writeBuff , strlen(writeBuff));
			bzero(writeBuff, sizeof(writeBuff));
			bzero(readBuff, sizeof(readBuff)); 
			while((n = read(connfd,readBuff,sizeof(readBuff)))<=0);
			continue;
		}	
		else 
			printf("\nCommand Requested: %s\n",request);

		if(type_request == 1 || type_request == 2 || type_request == 3 )
		{
			strcat(writeBuff,response);
			while(indexget_data != NULL)
			{
				sprintf(response, "%-40s| %-13c| %-10d| %-20s" , indexget_data->filename , indexget_data->type , indexget_data->size , ctime(&indexget_data->mtime));
				strcat(writeBuff,response);
				indexget_data = indexget_data->next;
			}
			fflush(stdout);
			strcat(writeBuff,"@@@");
			write(connfd , writeBuff , strlen(writeBuff));
		}

		else if(type_request == 4 || type_request == 5)
		{
			int c;

			while( hash_data != NULL )           
			{
				sprintf(response, "%-35s |   ",hash_data->filename);
				strcat(writeBuff,response);
				c=0;
				while(c < MD5_DIGEST_LENGTH)
				{
					sprintf(response, "%x",hash_data->hash[c]);
					strcat(writeBuff,response);
					c++;
				}
				sprintf(response, "\t %18s|",ctime(&hash_data->mtime));
				strcat(writeBuff,response);
				hash_data = hash_data->next;
			}
			strcat(writeBuff,"@@@");
			write(connfd , writeBuff , strlen(writeBuff));
		}
		else if(type_request == 7)
		{
			char copyrequest[1024] = {0};
			memcpy(writeBuff,"FileUpload Accept\n",strlen("FileUpload Accept\n"));
			write(connfd , writeBuff , strlen("FileUpload Accept\n"));
			memcpy(copyrequest,request,1024);
			char *size = strtok(copyrequest,"\n");
			size = strtok(NULL,"\n");
			long fsize = atol(size);
			char *request_data = NULL;
			request_data = strtok(request," \n");
			request_data = strtok(NULL," \n");
			int f = open(request_data, O_WRONLY | O_CREAT | O_EXCL, (mode_t)0600);
			int result = 0;
			if (f != -1) {

				result = lseek(f,fsize-1, SEEK_SET);
				result = write(f, "", 1);
			}
			if (result < 0 || f == -1) {
				close(f);
				perror("Error while opening file");
				return 1;
			}
			close(f);
			FILE *fp;
			fp = fopen(request_data,"wb");
			n = read(connfd, readBuff, sizeof(readBuff)-1);
			for(;;)
			{
				readBuff[n] = 0;
				if(readBuff[n-1] == '@' && readBuff[n-3] == '@' && readBuff[n-2] == '@')
				{
					readBuff[n-3] = 0;
					fwrite(readBuff,1,n-3,fp);
					fclose(fp);
					bzero(readBuff, n-3);
					break;
				}
				else
				{
					fwrite(readBuff,1,n,fp);
					bzero(readBuff, n);
				}
				n = read(connfd, readBuff, sizeof(readBuff)-1);
				if(n < 0)
					break;
			}
			bzero(writeBuff, 1024);

		}
		else if(type_request == 6)
		{
			FILE* fp;
			char fileDownloadName[1024];
			strcpy(fileDownloadName,request+13);
			int l = strlen(fileDownloadName);
			fileDownloadName[l-1]='\0';
			int t = access(fileDownloadName,F_OK);
			if( t != 0 )
			{
				bzero(writeBuff, sizeof(writeBuff));
				strcpy(writeBuff,strerror(errno));
				strcat(writeBuff,"@@@");
				write(connfd , writeBuff , strlen(writeBuff));
				bzero(writeBuff, sizeof(writeBuff));
				bzero(response, sizeof(response));
			}
			
			else{
			fp = fopen(fileDownloadName,"rb");
			size_t bytes_read;
			while(!feof(fp))
			{
				bytes_read = fread(response, 1, 1024, fp);
				memcpy(writeBuff,response,bytes_read);
				write(connfd , writeBuff , bytes_read);
				bzero(writeBuff, sizeof(writeBuff));
				bzero(response, sizeof(response));
			}
			memcpy(writeBuff,"@@@",3);
			write(connfd , writeBuff , 3);
			bzero(writeBuff, sizeof(writeBuff));
			fclose(fp);
			}
		}
		else if(type_request == 13)
		{
			int count = hist_count;
			strcat(writeBuff,response);
			while( count-- )
			{
				sprintf(response,"---->%s\n" , history[count]);
				strcat(writeBuff,response);
			}
			fflush(stdout);
			strcat(writeBuff,"@@@");
			write(connfd , writeBuff , strlen(writeBuff));
		}


		bzero(readBuff, sizeof(readBuff)); 
		bzero(writeBuff, sizeof(writeBuff));
		while((n = read(connfd,readBuff,sizeof(readBuff)))<=0);
	}
	close(connfd);
	wait(NULL);
}
int tcp_client(char *ip,char *connectportno)
{
	int sockfd = 0, n = 0;
	char readBuff[1024];
	char writeBuff[1024];
	char DownloadName[1024];
	char UploadName[1024];

	struct sockaddr_in serv_addr;
	int portno = atoi(connectportno);

	bzero(readBuff, sizeof(readBuff));
	bzero(writeBuff, sizeof(writeBuff));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Error : Could not create socket \n");
		return 1;
	} 

	bzero(&serv_addr, sizeof(serv_addr)); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno); 

	if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
	{
		printf("\n inet_pton error occured\n");
		return 1;
	} 

	while( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0);
	printf("Client is Connected now : \n");
	int a , count = 0 , filedownload = 0 , fileupload = 0;

	for(;;)
	{
		char *cresponse = malloc(10240);
		size_t bytes_read;


		time_t var = time(NULL);
		if( var - prev_time > 10 ){
			prev_time = var;
	//		printf("efdgh\n");fflush(stdout);
			strcpy(writeBuff,"FileHash --checkall");
			write(sockfd, writeBuff , strlen(writeBuff));
			n = read(sockfd, readBuff, sizeof(readBuff)-1);
			for(;;)
			{
				readBuff[n] = 0;
				if(readBuff[n-1] == '@' && readBuff[n-2] == '@' && readBuff[n-3] == '@')
				{
					readBuff[n-3] = 0;
					strcat(cresponse,readBuff);
					memset(readBuff, 0,strlen(readBuff));
					break;
				}
				else
				{
					strcat(cresponse,readBuff);
					memset(readBuff, 0,strlen(readBuff));
				}
				n = read(sockfd, readBuff, sizeof(readBuff)-1);
				if(n < 0)
					break;  
			}
			checkhash(cresponse);
			bzero(readBuff, sizeof(readBuff));
			bzero(writeBuff, sizeof(writeBuff));

			//	printf("%s\n",cresponse);  
		}      


		printf("\n>>>");
		filedownload = 0;
		fileupload = 0;
		FILE *fp = NULL;
		int i;

		fgets(writeBuff,sizeof(writeBuff),stdin);

		char *filename;
		char copy[1024];
		strcpy(copy,writeBuff);
		filename = malloc(1024);
		filename = strtok(copy," \n");

		if(strcmp(filename,"quit") == 0)
			break;

		if(strcmp(filename,"FileUpload") == 0)
		{
			fileupload = 1;
			filename = strtok(NULL," \n");
			strcpy(UploadName,filename);
			int t = access(UploadName,F_OK);
			if( t != 0 )
			{
				printf("Error: %s\n",strerror(errno));
				continue;

			}
						
			FILE *f = fopen(UploadName, "r");
			fseek(f, 0, SEEK_END);
			unsigned long len = (unsigned long)ftell(f);
			char size[1024];
			bzero(size, 1024);
			sprintf(size,"%ld\n",len);
			strcat(writeBuff,size);
			fclose(f);
		}

		if(strcmp(filename,"FileDownload") == 0)
		{
			filedownload = 1;
			filename = strtok(NULL," \n");
			strcpy(DownloadName,filename);
			fp = fopen(DownloadName,"wb");
		}

		write(sockfd, writeBuff , strlen(writeBuff));

		n = read(sockfd, readBuff, sizeof(readBuff)-1);
		//      size_t bytes_read;

		if(strcmp(readBuff,"FileUpload Accept\n") == 0)
		{
			printf("Upload Accepted\n");
			filehash(2,UploadName);
			int c =0;
			sprintf(cresponse, "%s, ",hash_data->filename);
			strcat(writeBuff,cresponse);
			while(c < MD5_DIGEST_LENGTH )
			{
				sprintf(cresponse, "%02x",hash_data->hash[c]);
				strcat(writeBuff,cresponse);
				c++;
			}
			sprintf(cresponse, ", %s",ctime(&hash_data->mtime));
			strcat(writeBuff,cresponse);

			write(sockfd , writeBuff , bytes_read);
				("%s\n",writeBuff);
			bzero(writeBuff,  sizeof(writeBuff));
			fp = fopen(UploadName,"rb");
			while(!feof(fp))
			{
				bytes_read = fread(cresponse, 1, 1024, fp);
				cresponse[1024] = 0;
				memcpy(writeBuff,cresponse,bytes_read);
				write(sockfd , writeBuff , bytes_read);
				bzero(writeBuff, sizeof(writeBuff));
				bzero(cresponse, sizeof(cresponse));
			}
			memcpy(writeBuff,"@@@",3);
			write(sockfd , writeBuff , 3);
			memset(writeBuff, 0, sizeof(writeBuff));
			memset(readBuff, 0, strlen(readBuff));
			fclose(fp);
		}

		else if(strcmp(readBuff,"FileUpload Deny\n") == 0)
		{
			printf("Upload Denied\n");
			memset(readBuff, 0,sizeof(readBuff));
			continue;
		}

		else 
		{
			for(;;)
			{
				readBuff[n] = 0;
				if(readBuff[n-1] == '@' && readBuff[n-2] == '@' && readBuff[n-3] == '@')
				{
					readBuff[n-3] = 0;
					if(filedownload == 1)
					{
						fwrite(readBuff,1,n-3,fp);
						fclose(fp);
					}
					else
						strcat(cresponse,readBuff);
					memset(readBuff, 0,strlen(readBuff));
					break;
				}
				else
				{
					if(filedownload == 1)
						fwrite(readBuff,1,n,fp);
					else
						strcat(cresponse,readBuff);
					memset(readBuff, 0,strlen(readBuff));
				}
				n = read(sockfd, readBuff, sizeof(readBuff)-1);
				if(n < 0)
					break;
			}
		}

		if(filedownload == 0)
			printf("%s\n",cresponse);
		else 
			printf("File Downloaded\n");

		if(n < 0)
			printf("\n Read error \n");
		bzero(readBuff, sizeof(readBuff));
		bzero(writeBuff, sizeof(writeBuff));
	}
	return 0;
}
