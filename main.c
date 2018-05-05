#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libsocks6msg/socks6msg.h"

#define REQ "GET / HTTP/1.0\r\n\r\n"

void usage()
{
	fprintf(stderr, "usage: socksget <proxy IP> <proxy port> <target>\n");
	exit(EXIT_FAILURE);
}

void s6m_perror(const char *msg, int err)
{
	fprintf(stderr, "%s: %s\n", msg, S6M_Error_Msg(err));
}

int main(int argc, char **argv)
{
	if (argc != 4)
		usage();
	
	struct S6M_Request req = {
		.code = SOCKS6_REQUEST_CONNECT,
		.addr = {
			.type = SOCKS6_ADDR_DOMAIN,
			.domain = argv[3],
		},
		.port = 80,
		.optionSet = {
			.tfo = 1,
		},
	};
	
	char buf[1500];
	
	ssize_t req_size = S6M_Request_Pack(&req, (uint8_t *)buf, 1500);
	if (req_size < 0)
	{
		s6m_perror("request pack", req_size);
		return EXIT_FAILURE;
	}
	memcpy(buf + req_size, REQ, strlen(REQ));
	req_size += strlen(REQ);
	
	int sock;
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket");
		return EXIT_FAILURE;
	}
	
	struct sockaddr_in proxy = {
		.sin_family = AF_INET,
		.sin_port = htons(atoi(argv[2])),
		.sin_addr = { .s_addr = inet_addr(argv[1]) },
	};
	
	int err = sendto(sock, (const void *)buf, req_size, MSG_FASTOPEN, (const struct sockaddr *)&proxy, sizeof(struct sockaddr_in));
	if (err < 0)
	{
		perror("sendto");
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
		
		if (stage == RECV_AUTHREP)
		{
			struct S6M_AuthReply *auth_rep;
			ssize_t auth_size = S6M_AuthReply_Parse((uint8_t *)buf + offset, sizeof(buf) - offset, &auth_rep);
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
			S6M_AuthReply_Free(auth_rep);
			//fprintf(stderr, "got auth reply\n");
			stage = RECV_OPREP;
		}
		else if (stage == RECV_OPREP)
		{
			struct S6M_OpReply *op_rep;
			ssize_t op_size = S6M_OpReply_Parse((uint8_t *)buf + offset, sizeof(buf) - offset, &op_rep);
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
			S6M_OpReply_Free(op_rep);
			//fprintf(stderr, "got op reply\n");
			stage = RECV_DATA;
		}
		else if (stage == RECV_DATA)
		{
			buf[offset + bytes] = '\0';
			printf("%s", buf + offset);
		}
		
		offset += bytes;
	}
	
	printf("\n");
	
	close(sock);
	
	return EXIT_SUCCESS;
}
