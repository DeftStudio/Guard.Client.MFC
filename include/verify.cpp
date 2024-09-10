#include "verify.h"
#include <codecvt>
#include <locale>
std::string verify::trim_quotes(const std::string& str)
{
	if (str.empty()) {
		return str;
	}

	// Check if the first and last characters are double quotes
	if (str.front() == '"' && str.back() == '"') {
		// Remove the quotes
		return str.substr(1, str.size() - 2);
	}

	// If no quotes, return the original string
	return str;
}

void verify::handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

std::string verify::encryptWithPublicKey(const std::string& publicKeyPem, const std::string& data)
{
	BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), -1);
	EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!publicKey) {
		//std::cerr << "Error loading public key." << std::endl;
		handleErrors();
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
	if (!ctx) {
		//std::cerr << "Error creating context." << std::endl;
		handleErrors();
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		//std::cerr << "Error initializing encryption." << std::endl;
		handleErrors();
	}

	// ʹ�� SHA256 ��Ϊ OAEP ���Ĺ�ϣ����
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
		//std::cerr << "Error setting padding or hash function." << std::endl;
		handleErrors();
	}

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
		//std::cerr << "Error determining buffer length." << std::endl;
		handleErrors();
	}

	std::vector<unsigned char> encryptedData(outlen);
	if (EVP_PKEY_encrypt(ctx, encryptedData.data(), &outlen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
		//std::cerr << "Error encrypting data." << std::endl;
		handleErrors();
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(publicKey);
	BIO_free(bio);

	return base64Encode(encryptedData.data(), outlen);
}

EVP_PKEY* verify::loadPublicKeyFromString(const std::string& public_key_str)
{
	BIO* bio = BIO_new_mem_buf(public_key_str.data(), public_key_str.size());
	if (!bio)
		handleErrors();

	EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!public_key)
		handleErrors();

	return public_key;
}

bool verify::verifySignature(const std::string& publicKeyPem, const std::string& data, const std::vector<unsigned char>& signature)
{
	EVP_PKEY* evp_pkey = nullptr;
	bool result = false;

	// ��ȡ��Կ
	BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), publicKeyPem.size());
	evp_pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!evp_pkey) {
		//std::cerr << "Failed to read public key." << std::endl;
		return false;
	}

	// ���� EVP_PKEY_CTX ������
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_pkey, nullptr);
	if (!ctx) {
		//std::cerr << "Create EVP_PKEY_CTX error" << std::endl;
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// ��ʼ��ǩ����֤
	if (EVP_PKEY_verify_init(ctx) <= 0) {
		//std::cerr << "Failed to initialize signature verification. Procedure" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// ����ǩ�����ģʽΪ PKCS#1 v1.5
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		//std::cerr << "set PKCS#1 v1.5 error" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// ���ù�ϣ�㷨Ϊ SHA256
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		//std::cerr << "Description Failed to set the signature hashing algorithm" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// �������ݵ� SHA256 ��ϣ
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

	// ��֤ǩ��
	int ret = EVP_PKEY_verify(ctx, signature.data(), signature.size(), hash, SHA256_DIGEST_LENGTH);

	if (ret == 1) {
		result = true;
	}
	// ������Դ
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_pkey);

	return result;
}

SYSTEMTIME verify::ConvertTimestampToSystemTime(uint64_t timestamp)
{
	// ����Windows����ʼʱ�䣺1601��1��1��
	const ULONGLONG EPOCH_DIFFERENCE = 11644473600ULL; // 1970��1601��֮�������
	const ULONGLONG SECONDS_TO_100NS = 10000000ULL;    // 1�����100����
	const int BEIJING_TIME_OFFSET = 8 * 3600;          // ����ʱ���UTC��8Сʱ


	// ��UNIXʱ���ת��Ϊ����ʱ��
	ULONGLONG beijingTimestamp = timestamp + BEIJING_TIME_OFFSET;

	// ��UNIXʱ���ת��Ϊ��100����Ϊ��λ��Windowsʱ��
	ULONGLONG windowsTimestamp = (beijingTimestamp + EPOCH_DIFFERENCE) * SECONDS_TO_100NS;

	// ��ʱ���ת��ΪFILETIME�ṹ
	FILETIME ft;
	ft.dwLowDateTime = static_cast<DWORD>(windowsTimestamp & 0xFFFFFFFF);
	ft.dwHighDateTime = static_cast<DWORD>(windowsTimestamp >> 32);

	// ��FILETIMEת��ΪSYSTEMTIME
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);

	return st;

}

void verify::HearthFunc(const std::string& data)
{
	//����ǩ��
	std::string temp = base64Decode(this->m_sign);
	//����ǩ��
	std::vector<unsigned char> m_signature(temp.begin(), temp.end());
	//��֤ǩ��
	bool verified = verifySignature(this->m_publickey, data, m_signature);
	if (!verified) {
		MessageBox(NULL, L"�Ƿ�����",L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
		this->m_Verify = false;
		exit(0);
	}
}

bool verify::Stripping_Equipment(const std::string& card)
{
	// ���� �����
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {"content-type", "application/json"} };
	//�Ƚ��ܹ�Կ
	this->m_publickey = base64Decode(PUBLIC_KEY);
	//���ܿ������ݷ���
	CradStr = encryptWithPublicKey(this->m_publickey, card);
	this->m_j_patch["msg"] = CradStr;
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post(oxorany("/api/unbind"), headers, this->m_request_packet, "application/json"))
	{
		//ȡֵ
		auto jj = json::parse(res->body);
		//check
		json check = jj["check"];
		json si = check["sign"];
		m_unix = check["unix"];
		//status
		json status = jj["status"];
		json ret = status["code"];
		json retstr = status["msg"];
		int rcode = ret;
		if (rcode != 1000)
		{
			// ʹ�� wstring_convert ����ת��
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring unicode_str = converter.from_bytes(retstr);
			//�����¼���
			MessageBox(NULL, unicode_str.c_str(), L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
			this->m_Unbind = false;
			return false;
		}
		else
		{
			//ȡ��ǩ��ֵ
			this->m_sign = trim_quotes(si.dump());
			//����
			HearthFunc(card);
			//�����¼���
			//std::cout << trim_quotes(retstr) << std::endl;
			this->m_Unbind = true;
			GetUnix();
			return true;
		}
	}
	else {
		MessageBox(NULL, L"���粻�ȶ� ���ܷ��������ȶ�����������粻�ȶ�", L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
		return false;
	}
}

bool verify::Login(const std::string& card)
{
	// ���� �����
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {"content-type", "application/json"} };
	//�Ƚ��ܹ�Կ
	this->m_publickey = base64Decode(PUBLIC_KEY);
	//���ܿ������ݷ���
	CradStr = encryptWithPublicKey(this->m_publickey, card);
	this->m_j_patch["msg"] = CradStr;
	this->m_j_patch["device_code"] = GenerateSystemSerialNumber(); //������
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post("/api/check", headers, this->m_request_packet, "application/json"))
	{
		//ȡֵ
		auto jj = json::parse(res->body);
		//check
		json check = jj["check"];
		json si = check["sign"];
		m_unix = check["unix"];
		//status
		json status = jj["status"];
		json ret = status["code"];
		json retstr = status["msg"];
		int rcode = ret;
		if (rcode != 1000)
		{
			// ʹ�� wstring_convert ����ת��
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring unicode_str = converter.from_bytes(retstr);
			//�����¼���
			MessageBox(NULL, unicode_str.c_str(), L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
			this->m_Verify = false;
			return false;
		}
		else
		{
			//ȡ��ǩ��ֵ
			this->m_sign = trim_quotes(si.dump());
			//����
			HearthFunc(card);
			//�����¼���
			//std::cout << trim_quotes(retstr) << std::endl;
			this->m_Verify = true;
			GetUnix();
			return true;
		}
	}
	else {
		MessageBox(NULL, L"���粻�ȶ� ���ܷ��������ȶ�����������粻�ȶ�", L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
		return false;
	}
}

bool verify::GetVerify()
{
	return this->m_Verify;
}

bool verify::GetUnbind()
{
	return this->m_Unbind;
}

void verify::GetUnix()
{
	SYSTEMTIME time = ConvertTimestampToSystemTime(this->m_unix);
	char str[256]{};
	sprintf_s(str, "����ʱ��: %d-%d-%d-%d:%d:%d", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
	MessageBoxA(NULL,str,"Caption",MB_OK);
}

verify::verify()
{
}
verify::verify(const std::string& card)
{
	// service ip
	// ���� �����
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {"content-type", "application/json"} };
	//�Ƚ��ܹ�Կ
	this->m_publickey = base64Decode(PUBLIC_KEY);
	//���ܿ������ݷ���
	CradStr = encryptWithPublicKey(this->m_publickey,card);
	this->m_j_patch["msg"] = CradStr;
	this->m_j_patch["device_code"] = GenerateSystemSerialNumber(); //������
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post("/api/check", headers, this->m_request_packet, "application/json"))
	{
		//ȡֵ
		auto jj = json::parse(res->body);
		//check
		json check = jj["check"];
		json si = check["sign"];
		//status
		json status = jj["status"];
		json ret = status["code"];
		json retstr = status["msg"];
		int rcode = ret;
		if (rcode != 1000)
		{
			// ʹ�� wstring_convert ����ת��
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring unicode_str = converter.from_bytes(retstr);
			//�����¼���
			MessageBox(NULL, unicode_str.c_str(), L"Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
			this->m_Verify = false;
			return;
		}
		else
		{
			//ȡ��ǩ��ֵ
			this->m_sign = trim_quotes(si.dump());
			//����
			HearthFunc(card);
			//�����¼���
			//std::cout << trim_quotes(retstr) << std::endl;
			this->m_Verify = true;
			return;
		}
	}
	else {
		MessageBoxA(NULL, "���粻�ȶ� ���ܷ��������ȶ�����������粻�ȶ�", "Caption", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
		return ;
	}
}
verify::~verify()
{
}
