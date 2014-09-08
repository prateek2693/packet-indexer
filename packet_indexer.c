#define __USE_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */
#include <netinet/ip.h>  
#include <string.h>

typedef u_int32_t       tcp_seq;

struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */

		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};


int end_flag=0;
int packet_count=0;
int src[4][1000][256],dst[4][1000][256], port[2][1000][65536], proto[1000][2], temp;
long int j,k,digit_count,digit_type;


int query_result[1000];//array to hold packet numbers of the packets satisfying the queries
int sub1result[1000],sub2result[1000];
int offsets[1000];

void packet_indexer(){
	int i;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr; /* pcap.h */
	

	long int indir_offset=0;

	char *token;
	int token_int;

	descr = pcap_open_offline("1.cap",errbuf);

	 if(descr == NULL)
		{
		printf("pcap_open_offline(): %s\n",errbuf);
		exit(1);
		} 

	const struct ip* iphdr;
	const struct sniff_tcp* tcp;
	const struct UDP_hdr *udp;

	FILE *indir,*sip[4],*dip[4],*port_f[2],*proto_f;
			
	//file openings

	indir=fopen("resources/Indirection.txt","w");
	sip[0]=fopen("resources/Source1.txt","w");
	sip[1]=fopen("resources/Source2.txt","w");
	sip[2]=fopen("resources/Source3.txt","w");
	sip[3]=fopen("resources/Source4.txt","w");
	dip[0]=fopen("resources/Destination1.txt","w");
	dip[1]=fopen("resources/Destination2.txt","w");
	dip[2]=fopen("resources/Destination3.txt","w");
	dip[3]=fopen("resources/Destination4.txt","w");
	port_f[0]=fopen("resources/SourcePort.txt","w");
	port_f[1]=fopen("resources/DestinPort.txt","w");
	proto_f= fopen("resources/Protocol.txt","w");
	

	//Generating Bitmap From Packets
	
	while(end_flag==0){
		indir_offset=ftell(pcap_file(descr));
		
		packet = pcap_next(descr,&hdr);
		if(packet != NULL){
		fprintf(indir,"%ld\n",indir_offset);  
			++packet_count;		   

			/* jump past the ethernet header */
			iphdr = (struct ip*)(packet + sizeof(struct ether_header));
			/*printf("\nPacket Number:%d\n",packet_count);
			printf("Source:%s\n",inet_ntoa(iphdr->ip_src));
			printf("Destination:%s\n",inet_ntoa(iphdr->ip_dst));*/

			if(iphdr->ip_p==6){

				//printf("Protocol:TCP\n");
				tcp = (struct sniff_tcp*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
				/*printf("Source Port:%d\n",ntohs(tcp->th_sport));
				printf("Destination Port:%d\n",ntohs(tcp->th_dport));*/
				port[0][packet_count-1][ntohs(tcp->th_sport)]=1;
				port[1][packet_count-1][ntohs(tcp->th_dport)]=1;
				proto[packet_count-1][0]=1;
				
			}

			else if(iphdr->ip_p==17){
				//printf("Protocol:UDP\n"); 		
	                	udp=(struct UDP_hdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
				/*printf("Source Port:%d\n",ntohs(udp->uh_sport));
				printf("Destination Port:%d\n",ntohs(udp->uh_dport));*/
				port[0][packet_count-1][ntohs(udp->uh_sport)]=1;
				port[1][packet_count-1][ntohs(udp->uh_dport)]=1;
				proto[packet_count-1][1]=1;

		
 	 		}
				//Indirection Array
			
			
			
			//Source IP Tokenizing and normal bitmap index creation
			token = strtok(inet_ntoa(iphdr->ip_src), ".");

			 i=0;
			while( token != NULL ){
				token_int=atoi(token);
				src[i++][packet_count-1][token_int]=1;
				token = strtok(NULL, ".");
			}

			//Destination IP Tokenizing and normal bitmap index creation
			token = strtok(inet_ntoa(iphdr->ip_dst), ".");

			 i=0;
			while( token != NULL ){
				token_int=atoi(token);
				dst[i++][packet_count-1][token_int]=1;
				token = strtok(NULL, ".");
		
			}
			
	

		}
		else end_flag=1;
		
	}//end of while
			
	//Source Compression
	
	for(i=0;i<4;i++){
		for(k=0;k<256;k++){
			for(j=0;j<packet_count;j++){
				if(j==0){
					if(src[i][j][k]==0){
						digit_type=0;
						digit_count=1;
					}
					else if(src[i][j][k]==1){
						digit_type=1;
						digit_count=1;
					}
				}//if-j
				else{
					if(digit_type==src[i][j][k]){
					digit_count++;
					}
					else {
						fprintf(sip[i],"%ld ",digit_count);
						fprintf(sip[i],"%ld ",digit_type);						
						digit_type=src[i][j][k];
						digit_count=1;
					}
				}
			}//j
		fprintf(sip[i],"%ld ",digit_count);
		fprintf(sip[i],"%ld ",digit_type);
		fprintf(sip[i],"\n");
		}//k
	}//i


	//Destination comperssion

	for(i=0;i<4;i++){
		for(k=0;k<256;k++){
			for(j=0;j<packet_count;j++){
				if(j==0){
					if(dst[i][j][k]==0){
						digit_type=0;
						digit_count=1;
					}
					else if(dst[i][j][k]==1){
						digit_type=1;
						digit_count=1;
					}
				}//if-j
				else{
					if(digit_type==dst[i][j][k]){
					digit_count++;
					}
					else {
						fprintf(dip[i],"%ld ",digit_count);
						fprintf(dip[i],"%ld ",digit_type);						
						digit_type=dst[i][j][k];
						digit_count=1;
					}
				}
			}//j
		fprintf(dip[i],"%ld ",digit_count);
		fprintf(dip[i],"%ld ",digit_type);
		fprintf(dip[i],"\n");
		}//k
	}//i

	
	//Port comperssion
	

	for(i=0;i<2;i++){
		for(k=0;k<65536;k++){
			for(j=0;j<packet_count;j++){
				if(j==0){
					if(port[i][j][k]==0){
						digit_type=0;
						digit_count=1;
					}
					else if(port[i][j][k]==1){
						digit_type=1;
						digit_count=1;
					}
				}//if-j
				else{
					if(digit_type==port[i][j][k]){
						digit_count++;
						}
					else {
						fprintf(port_f[i],"%ld ",digit_count);
						fprintf(port_f[i],"%ld ",digit_type);						
						digit_type=port[i][j][k];
						digit_count=1;
					}
				}
			}//j
			fprintf(port_f[i],"%ld ",digit_count);
			fprintf(port_f[i],"%ld ",digit_type);
			fprintf(port_f[i],"\n");
		}//k
	}//i
	
	
	//End Port Compression

	//protocol compression

	for(k=0;k<2;k++){
		for(j=0;j<packet_count;j++){
			if(j==0){
				if(proto[j][k]==0){
					digit_type=0;
					digit_count=1;
				}
				else if(proto[j][k]==1){
					digit_type=1;
					digit_count=1;
				}
			}//if-j
			else{
				if(digit_type==proto[j][k]){
					digit_count++;
					}
				else {
					fprintf(proto_f,"%ld ",digit_count);
					fprintf(proto_f,"%ld ",digit_type);						
					digit_type=proto[j][k];
					digit_count=1;
				}
			}
		}//j
		fprintf(proto_f,"%ld ",digit_count);
		fprintf(proto_f,"%ld ",digit_type);
		fprintf(proto_f,"\n");
	}//k
	

	fclose(indir);
	fclose(sip[0]);
	fclose(sip[1]);
	fclose(sip[2]);
	fclose(sip[3]);
	fclose(dip[0]);
	fclose(dip[1]);
	fclose(dip[2]);
	fclose(dip[3]);
	fclose(port_f[0]);
	fclose(port_f[1]);
	fclose(proto_f);	
	pcap_close(descr);
}


void ip_query(char *value,int type,int query_type){
	//type0= SrcIP type1=DstIP
	//querytype : 0=mainquery 1=subquery1 2=subquery2
	char *token1,*token2,*token3,*token4;
	FILE* byte[4];
	
	//File opening based on soruce or destination
	if(type==0){
		byte[0]=fopen("resources/Source1.txt","r");
		byte[1]=fopen("resources/Source2.txt","r");
		byte[2]=fopen("resources/Source3.txt","r");
		byte[3]=fopen("resources/Source4.txt","r");
	}
	else if(type==1){
		byte[0]=fopen("resources/Destination1.txt","r");
		byte[1]=fopen("resources/Destination2.txt","r");
		byte[2]=fopen("resources/Destination3.txt","r");
		byte[3]=fopen("resources/Destination4.txt","r");
	}
	
	char str[80];
	strcpy(str,value);
	const char s[2]=".";
	token1=strtok(str,s);
	token2=strtok(NULL,s);
	token3=strtok(NULL,s);
	token4=strtok(NULL,s);
	//printf("%s\n%s\n%s\n%s\n",token1,token2,token3,token4);
	
	int i;
	//All stars
	if(!strcmp(token1,"*") && !strcmp(token2,"*") && !strcmp(token3,"*") && !strcmp(token4,"*")){
			if(query_type==0){
					for(i=0;i<packet_count;i++)
						query_result[i]=1;
			}
			else if(query_type==1){
					for(i=0;i<packet_count;i++)
						sub1result[i]=1;
			}
			else if(query_type==2){
					for(i=0;i<packet_count;i++)
						sub2result[i]=1;
			}
	}
	
	else{
		int byte1result[1000],byte2result[1000],byte3result[1000],byte4result[1000];
		
		//Byte1
		if(strcmp(token1,"*")!=0){
			int token_val=atoi(token1);
			char line[1000];
			
			while(token_val+1>0){
				fgets(line,1000,byte[0]);	
				token_val--;			
			}
			
			//printf("Line of byte1:%s",line);
			
			int j=0,k=0,l;
			
			while(line[j]!='\n'){
				
				int count=0;
				while(line[j]!=' '){					
				count=count*10+	line[j]-48;
				j++;	
				}
				
				for(l=0;l<count;l++)
					byte1result[k++]=line[j+1]-48;
				j=j+3;
			}
		}
		
		else{			
			for(i=0;i<packet_count;i++)
				byte1result[i]=1;			
		}
		
		//Byte2
		if(strcmp(token2,"*")!=0){
			int token_val=atoi(token2);
			char line[1000];
			
			while(token_val+1>0){
				fgets(line,1000,byte[1]);
				token_val--;				
			}
			
			//printf("Line of byte2:%s",line);
			
			int j=0,k=0,l;
			while(line[j]!='\n'){
				
				int count=0;
				while(line[j]!=' '){					
				count=count*10+	line[j]-48;
				j++;	
				}
				
				for(l=0;l<count;l++)
					byte2result[k++]=line[j+1]-48;
				j=j+3;
			}
		}
		
		else{			
			for(i=0;i<packet_count;i++)
				byte2result[i]=1;			
		}
		
		//Byte3
		if(strcmp(token3,"*")!=0){
			int token_val=atoi(token3);
			char line[1000];
			
			while(token_val+1>0){
				fgets(line,1000,byte[2]);
				token_val--;				
			}
			
			//printf("Line of byte3:%s",line);
			
			int j=0,k=0,l;
			while(line[j]!='\n'){
				
				int count=0;
				while(line[j]!=' '){					
				count=count*10 + line[j] - 48;
				j++;	
				}
				
				for(l=0;l<count;l++)
					byte3result[k++]=line[j+1]-48;
				j=j+3;
			}
		}
		
		else{			
			for(i=0;i<packet_count;i++)
				byte3result[i]=1;			
		}
		
		//Byte4
		if(strcmp(token4,"*")!=0){
			int token_val=atoi(token4);
			char line[1000];
			
			while(token_val+1>0){
				fgets(line,1000,byte[3]);
				token_val--;				
			}
			
			//printf("Line of byte4:%s",line);
			
			int j=0,k=0,l;
			while(line[j]!='\n'){
				
				int count=0;
				while(line[j]!=' '){					
				count=count*10+	line[j]-48;
				j++;	
				}
				
				for(l=0;l<count;l++)
					byte4result[k++]=line[j+1]-48;
				j=j+3;
			}
		}
		
		else{			
			for(i=0;i<packet_count;i++)
				byte4result[i]=1;			
		}
		
		//Combing the byte queries
		if(query_type==0){
			for(i=0;i<packet_count;i++)
						query_result[i]=byte1result[i] && byte2result[i] && byte3result[i] && byte4result[i];
		}
		else if(query_type==1){
			for(i=0;i<packet_count;i++)
						sub1result[i]=byte1result[i] && byte2result[i] && byte3result[i] && byte4result[i];
		}
		
		else if(query_type==2){
			for(i=0;i<packet_count;i++)
						sub2result[i]=byte1result[i] && byte2result[i] && byte3result[i] && byte4result[i];
		}
	
		//Printing for testing
		/*for(i=0;i<packet_count;i++){
		printf("%d: %d && %d && %d && %d = %d\n",i+1,byte1result[i],byte2result[i],byte3result[i],byte4result[i],sub1result[i]);
		}*/
	}
		
	fclose(byte[0]);
	fclose(byte[1]);
	fclose(byte[2]);
	fclose(byte[3]);
}

void port_query(char *value,int type,int query_type){
	//type0= SrcPort type1=DstPort
	//querytype : 0=mainquery 1=subquery1 2=subquery2
	FILE* port_file;
	
	char str[50];
	strcpy(str,value);
	
	if(type==0)
	{
			port_file=fopen("resources/SourcePort.txt","r");
	}
	else if(type==1)
	{
			port_file=fopen("resources/DestinPort.txt","r");
	}
	
	int i;
	//Star
	if(!strcmp(str,"*")){
			if(query_type==0){
					for(i=0;i<packet_count;i++)
						query_result[i]=1;
			}
			else if(query_type==1){
					for(i=0;i<packet_count;i++)
						sub1result[i]=1;
			}
			else if(query_type==2){
					for(i=0;i<packet_count;i++)
						sub2result[i]=1;
			}
	}
	
	//Particular number
	else{
			int port_num = atoi(str);
			//printf("Port number=%d\n",port_num);
			char line[1000];
			
			while(port_num+1>0){
				fgets(line,1000,port_file);	
				port_num--;			
			}
			
			//printf("Line of port:%s",line);
			
			int j=0,k=0,l;
			
			while(line[j]!='\n'){
				int count=0;
				while(line[j]!=' '){					
				count=count*10+	line[j]-48;
				j++;	
				}
				//printf("Count:%d\n",count);
				for(l=0;l<count;l++){
					
					if(query_type==0)
					query_result[k++]=line[j+1]-48;
					
					else if(query_type==1)
					sub1result[k++]=line[j+1]-48;
					
					else if(query_type==2)
					sub2result[k++]=line[j+1]-48;
										
				}
				j=j+3;
			}
	}
	
	fclose(port_file);
}

void protocol_query(char* value,int query_type){	
	//querytype : 0=mainquery 1=subquery1 2=subquery2
	FILE* protocol_file;
	
	char str[50];
	strcpy(str,value);
	
	
	protocol_file=fopen("resources/Protocol.txt","r");
	
	
	int i;
	//Star
	if(!strcmp(str,"*")){
			if(query_type==0){
					for(i=0;i<packet_count;i++)
						query_result[i]=1;
			}
			else if(query_type==1){
					for(i=0;i<packet_count;i++)
						sub1result[i]=1;
			}
			else if(query_type==2){
					for(i=0;i<packet_count;i++)
						sub2result[i]=1;
			}
	}
	
	//Particular number
	else{
			int protocol_num = atoi(str);
			//printf("Protocol number=%d\n",protocol_num);
			char line[1000];
			
			while(protocol_num+1>0){
				fgets(line,1000,protocol_file);	
				protocol_num--;			
			}
			
			//printf("Line of protocol:%s",line);
			
			int j=0,k=0,l;
			
			while(line[j]!='\n'){
				int count=0;
				while(line[j]!=' '){					
				count=count*10+	line[j]-48;
				j++;	
				}
				//printf("Count:%d\n",count);
				for(l=0;l<count;l++){
					
					if(query_type==0)
					query_result[k++]=line[j+1]-48;
					
					else if(query_type==1)
					sub1result[k++]=line[j+1]-48;
					
					else if(query_type==2)
					sub2result[k++]=line[j+1]-48;
										
				}
				j=j+3;
			}
	}
	
	fclose(protocol_file);
}

void single_query(char* query_string,int query_type){
		char* equ_pos;
		char key[50],value[50];
		
		equ_pos=strchr(query_string,'=');
		strncpy(key,query_string,equ_pos-query_string);	
		strncpy(value,query_string+(equ_pos-query_string)+1,query_string+strlen(query_string)-equ_pos);	
		
		//printf("Key:%s\n",key);
		//printf("Value:%s\n",value);
		
		if(strcasecmp(key,"SrcIP")==0){
			ip_query(value,0,query_type);					
		}
		else if(strcasecmp(key,"DstIP")==0){
			ip_query(value,1,query_type);					
		} 
		else if(strcasecmp(key,"SrcPort")==0){
			port_query(value,0,query_type);					
		}
		else if(strcasecmp(key,"DstPort")==0){
			port_query(value,1,query_type);					
		}
		else if(strcasecmp(key,"Protocol")==0){
			protocol_query(value,query_type);					
		}
			
}

void query_processor(){
	
		
		char str[50];
		char subquery1[50],subquery2[50];
		
		char bpf_query[50];
		struct bpf_program bpf_prog;
		
		
		printf("\nIndex Query Options for fields:\n SrcIP or DstIP or SrcPort or DstPort or Protocol\n Protocol=0 for TCP else 1 for UDP\n");
		printf("\nExample: protocol=1\n"); 
		
		printf("\nPlease Enter Your Index Query: ");
		scanf("%s",str);
		printf("\nYour Index Query Was: %s",str);				
		
		char* pos;
		
		//OR
		if((pos=strchr(str,';'))!=NULL){
			
			strncpy(subquery1,str,pos-str);	
			subquery1[pos-str]='\0';
			strncpy(subquery2,str+(pos-str)+1,str+strlen(str)-pos);	
			printf("\nSubquery1: %s",subquery1);
			printf("\nOR");
			printf("\nSubquery2: %s\n",subquery2);	
			
			single_query(subquery1,1);
			single_query(subquery2,2);
			
			int i;
			for(i=0;i<packet_count;i++){
				query_result[i]=sub1result[i] || sub2result[i];
			}
		}
		
		//AND
		else if((pos=strchr(str,':'))!=NULL){
			
			strncpy(subquery1,str,pos-str);	
			subquery1[pos-str]='\0';
			strncpy(subquery2,str+(pos-str)+1,str+strlen(str)-pos);	
			printf("\nSubquery1: %s",subquery1);
			printf("\nAND");
			printf("\nSubquery2: %s\n",subquery2);	
			
			single_query(subquery1,1);
			single_query(subquery2,2);
			
			int i;
			for(i=0;i<packet_count;i++){
				query_result[i]=sub1result[i] && sub2result[i];
			}
			
		}
		
		//Single big query
		else{
			single_query(str,0);
		}
		
		//Populate the indirection from the indirection array file
		FILE *indir_file;
		indir_file=fopen("resources/Indirection.txt","r");
		int i;
		int indir_arr[1000];
		char line[1000]; 
		for(i=0;i<packet_count;i++)
			{
				fgets(line,1000,indir_file);
				
				int j=0;
			    int count=0;
			    
				while(line[j]!='\n'){					
					count=count*10+	line[j]-48;
					j++;	
				}
				
				indir_arr[i] = count;
			}
			
		int offsets_arr_length=0;
		for(i=0;i<packet_count;i++)
			{
					if(query_result[i]==1)
						{
							offsets[offsets_arr_length++]=indir_arr[i];			
							
						}
			}
			
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* descr;
		const u_char *packet;
		struct pcap_pkthdr hdr;			
		const struct ip* iphdr;
		const struct sniff_tcp* tcp;
		const struct UDP_hdr *udp;
		
		descr = pcap_open_offline("1.cap",errbuf);
		if(descr == NULL)
			{
			printf("pcap_open_offline(): %s\n",errbuf);
			exit(1);
			} 
			
		printf("\n%d packets met with the requirements of index query\n",offsets_arr_length);
		printf("\nPlease Enter Your BPF query:");
		getchar();
		gets(bpf_query);
		printf("Your BPF query was: %s\n",bpf_query);
			
		printf("\nSatisfying packets:\n");
			
		for(k=0;k<offsets_arr_length;k++)
			{	
					
					fseek(pcap_file(descr),offsets[k],SEEK_SET);
					
					if (pcap_compile(descr, &bpf_prog, (const char*)bpf_query, 0, PCAP_NETMASK_UNKNOWN) == -1) {
						printf("Couldn't parse filter %s: %s\n", bpf_query, pcap_geterr(descr));
						}

					if (pcap_setfilter(descr, &bpf_prog) == -1) {
						printf("Couldn't install filter %s: %s\n", bpf_query, pcap_geterr(descr));
						}	
						
					packet = pcap_next(descr,&hdr);
					
					//printf("\n%d",offsets[k]+16+hdr.len);
					//printf("\n%d",ftell(pcap_file(descr)));
					
					if(packet!=NULL && offsets[k]+16+hdr.len ==ftell(pcap_file(descr)))
					{
						iphdr = (struct ip*)(packet + sizeof(struct ether_header));
						printf("\nPacket Number:%d\n",k+1);
						printf("Packet Found at offset:%d\n",offsets[k]);
						printf("Source:%s\n",inet_ntoa(iphdr->ip_src));
						printf("Destination:%s\n",inet_ntoa(iphdr->ip_dst));
						
						if(iphdr->ip_p==6){					
							printf("Protocol:TCP\n");
							tcp = (struct sniff_tcp*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
							printf("Source Port:%d\n",ntohs(tcp->th_sport));
							printf("Destination Port:%d\n",ntohs(tcp->th_dport));							
						}
						else if(iphdr->ip_p==17){					
							printf("Protocol:UDP\n");
							udp=(struct UDP_hdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
							printf("Source Port:%d\n",ntohs(udp->uh_sport));
							printf("Destination Port:%d\n",ntohs(udp->uh_dport));						
						}
					
					}
			printf("\n");
	}
}

int main(int argc, char **argv)
{
	packet_indexer();
	
	query_processor();
	
} 
