#pragma once
#include "httplib.h"
#include "json.hpp"
#include <iostream>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <vector>
#include "base64.h"
#include "oxorany.h"
#include "machine_code.h"
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#define IP oxorany("120.26.116.132")
#define PORT oxorany(7779)
#define PUBLIC_KEY oxorany("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyMW5pc1kxMzg5eGdSUFo2NHkrVgowMjFPWlNhSmpFVVQ2YVBQSHVLaEJ5d2Z4SDk3ME9xckJpWStXVXJRd1M4NnBGem4ybDBPTnE5cWpJVTlUZURPCkhqY0pINzNUNDFRU2RxMWZDYTk4dThZUkwwcmRoZU1mMkh3d2E5ZDF3Q05GeHZCMmZuY0hKQ2JoU2xQcVIwMDEKR1ZQbkRMbVNJQXpjYitNTDJicTdQVkVINWdyalpwbWhjYk5WWER4bG5mZTFLbzhJTURFNVN2L1lOZXhrcmhWYgpZWXFaclNlcXRSZ0FkcmVFTDdmY2tQMlRoZ1ltNDNFaWV1Vmp5dkZTcko3cjlZRzRDTVVTZ0p1aFNFcEUySDNlCkFhVGNaUzlXd3JZMmdCaGNIbFZlbDN4bzNVNFVDRm42VTZQcTVQajd6RTArSFJwVmxSa1VjVkZ4YnI1Znc1QmUKMVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t")
class verify : public base64, public Machine_code
{
private:
	// ��Կ
	std::string m_publickey;
	// ��������
	std::string CradStr;
	//json msg data
	using json = nlohmann::json;
	json m_j_patch = R"(
	{
    "msg": "",
	"device_code":""
	})"_json;
	//request packet
	std::string m_request_packet;
	//verify vaule
	bool m_Verify = oxorany(false);
	// �⽉
	bool m_Unbind = oxorany(false);
	// ʱ���
	uint64_t m_unix = 0;
	//Sign vaule
	std::string m_sign;
	// ȡ˫����������
	std::string trim_quotes(const std::string& str);
	//�쳣����
	void handleErrors();
	// ʹ�ù�Կ��������
	std::string encryptWithPublicKey(const std::string& publicKeyPem, const std::string& data);
	// ���ַ������ع�Կ
	EVP_PKEY* loadPublicKeyFromString(const std::string& public_key_str);
	// ʹ�� EVP_PKEY_CTX ��֤ RSA+SHA256 ǩ�� ʹ�� PKCS#1 v1.5 ���ģʽ��֤ǩ��
	bool verifySignature(const std::string& publicKeyPem, const std::string& data, const std::vector<unsigned char>& signature);
	// ʱ�����SYSTEMTIME�ṹ��ת��
	SYSTEMTIME ConvertTimestampToSystemTime(uint64_t timestamp);
public:
	// ��ȡ��¼���
	bool GetVerify();
	// ��ȡ�����
	bool GetUnbind();
	// ��ȡ����ʱ��
	void GetUnix();
	// ����call
	void HearthFunc(const std::string& card);
	// ����豸
	bool Stripping_Equipment(const std::string& card);
	// ������¼
	bool Login(const std::string& card);
	// Verify Run
	verify();
	verify(const std::string& card);
	~verify();
};
inline verify g_Verify;