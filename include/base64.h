#pragma once
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>
#include <iostream>
class base64
{
public:
	//����
	std::string base64Encode(const unsigned char* buffer, size_t length);
	//����
	std::string base64Decode(const std::string& encoded_string);
};

