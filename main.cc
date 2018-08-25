#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <socks6msg/socks6msg.h>
#include <socks6msg/socks6msg.hh>
#include <vector>

#define REQ "GET / HTTP/1.0\r\n\r\n"

void usage()
{
	fprintf(stderr, "usage: socksget <proxy IP> <proxy port> <target>\n");
	exit(EXIT_FAILURE);
}

void s6m_perror(const char *msg, int err)
{
	fprintf(stderr, "%s: %s\n", msg, S6M_Error_msg((S6M_Error)err));
}

int main(int argc, char **argv)
{
	if (argc != 5)
		usage();


	in6_addr prx;
	in6_addr srv;
	in6_addr detour;

	inet_pton(AF_INET6, argv[1], &prx);
	inet_pton(AF_INET6, argv[4], &detour);
	inet_pton(AF_INET6, argv[3], &srv);
	
	struct S6M::Request req(SOCKS6_REQUEST_CONNECT, S6M::Address(srv), 80, 0);
	std::vector<in6_addr> detours;
	detours.push_back(detour);
	req.getOptionSet()->setForwardSegments(detours);
	
	uint8_t buf[1500];

	ssize_t req_size = req.pack(buf, sizeof(buf));
	
	memcpy(buf + req_size, REQ, strlen(REQ));
	req_size += strlen(REQ);
	
	int sock;
	
	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket");
		return EXIT_FAILURE;
	}
	
	struct sockaddr_in6 proxy;
	proxy.sin6_family = AF_INET6;
	proxy.sin6_port = htons(atoi(argv[2]));
	proxy.sin6_addr = prx;

	int err = connect(sock, (const struct sockaddr *)&proxy, sizeof(struct sockaddr_in6));
	if (err < 0)
	{
		perror("connect");
		return EXIT_FAILURE;
	}
	
	err = send(sock, (const void *)buf, req_size, 0);
	if (err < 0)
	{
		perror("send");
		return EXIT_FAILURE;
	}
	
	memset(buf, 0, sizeof(buf));
	
	enum
	{
		RECV_AUTHREP,
		RECV_OPREP,
		RECV_DATA,
	};
	
	int stage = RECV_AUTHREP;
	int offset = 0;
	
	while (1)
	{
		ssize_t bytes = recv(sock, buf + offset, sizeof(buf) - offset, 0);
		if (bytes == 0)
		{
			//fprintf(stderr, "connection closed\n");
			break;
		}
		if (bytes < 0)
		{
			perror("recv");
			return EXIT_FAILURE;
		}
		offset += bytes;
		
		if (stage == RECV_AUTHREP)
		{
			struct S6M_AuthReply *auth_rep;
			ssize_t auth_size = S6M_AuthReply_parse((uint8_t *)buf, offset, &auth_rep);
			if (auth_size == S6M_ERR_BUFFER)
				continue;
			if (auth_size < 0)
			{
				s6m_perror("auth reply parse", auth_size);
				return EXIT_FAILURE;
			}
			if (auth_rep->code != SOCKS6_AUTH_REPLY_SUCCESS)
			{
				fprintf(stderr, "authentication failed\n");
				return EXIT_FAILURE;
			}
			S6M_AuthReply_free(auth_rep);
			//fprintf(stderr, "got auth reply\n");
			stage = RECV_OPREP;
			
			offset -= auth_size;
			memmove(buf, buf + auth_size, offset);
		}
		if (stage == RECV_OPREP)
		{
			struct S6M_OpReply *op_rep;
			ssize_t op_size = S6M_OpReply_parse((uint8_t *)buf, offset, &op_rep);
			if (op_size == S6M_ERR_BUFFER)
				continue;
			if (op_size < 0)
			{
				s6m_perror("op reply parse", op_size);
				return EXIT_FAILURE;
			}
			if (op_rep->code != SOCKS6_OPERATION_REPLY_SUCCESS)
			{
				fprintf(stderr, "operation failed\n");
				return EXIT_FAILURE;
			}
			S6M_OpReply_free(op_rep);
			//fprintf(stderr, "got op reply\n");
			stage = RECV_DATA;
			
			offset -= op_size;
			memmove(buf, buf + op_size, offset);
		}
		if (stage == RECV_DATA)
		{
			buf[offset] = '\0';
			printf("%s", buf);
			offset = 0;
		}
	}
	
	printf("\n");
	
	close(sock);
	
	return EXIT_SUCCESS;
}
