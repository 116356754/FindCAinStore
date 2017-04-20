#include "FindCAinStore.h"
#pragma comment(lib, "crypt32.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

CFindCAinStore::CFindCAinStore(const char *cName):m_hSystemStore(NULL),m_pDesiredCert(NULL)
{
	if(m_hSystemStore = CertOpenSystemStore(
		0,                      // Encoding type not needed 
		// Set the system store location in 
		// the registry.
		cName))                 // Could have used other predefined 
		// system stores
		// including Trust, CA, or Root.
	{
		printf("Opened the root system store. \n");
	}
	else
	{
		printf( "Could not open the root system store.\n");
	}
}

bool CFindCAinStore::find_Cert(const char* lpszCertSubject){
	if((m_hSystemStore ==NULL)|(lpszCertSubject==NULL))
		return false;

	bool status = false;

	int len = strlen(lpszCertSubject)+1;
	wchar_t *pwstr = new wchar_t[len];
	memset(pwstr,0,len);
	c2w(pwstr,len,lpszCertSubject);

	// subject. 
	if(m_pDesiredCert=CertFindCertificateInStore(
		m_hSystemStore,
		MY_ENCODING_TYPE,           // Use X509_ASN_ENCODING.
		0,                          // No dwFlags needed. 
		CERT_FIND_ISSUER_STR,      // Find a certificate with a
		// subject that matches the string
		// in the next parameter.
		pwstr ,           // The Unicode string to be found
		// in a certificate's subject.
		NULL))                      // NULL for the first call to the
		// function. In all subsequent
		// calls, it is the last pointer
		// returned by the function.
	{
		printf("The desired certificate was found. \n");
		status = true;
	}
	else
	{
		printf("Could not find the desired certificate.\n");
		status = false;
	}

	delete [] pwstr;

	return status;
}

bool CFindCAinStore::create_cert(LPTSTR pszDestination){
	if(pszDestination == NULL) return false;

	char dirPath[MAX_PATH]={0};
	GetModuleFileName(NULL, dirPath, MAX_PATH );

	char drive[_MAX_DRIVE]={0};
	char dir[_MAX_DIR]={0};
	_splitpath(dirPath,drive,dir,NULL,NULL);

	const char *file_name = "CA.cer";  // Get temp name				

	char file_path[MAX_PATH]={0};
	sprintf(file_path,"%s%s%s",drive,dir,file_name);

	printf("%s\n",file_path);

	FILE *fp = NULL;
	fp = fopen(file_path, "w+");

	if(fp==NULL)
		return false;

	fputs(pszDestination, fp);
	fclose(fp);

	return true;
}

bool CFindCAinStore::createCAfile_base64()
{
	if(m_pDesiredCert ==NULL) return false;

	bool b_Result = false;

	DWORD nDestinationSize;
	if (CryptBinaryToString(m_pDesiredCert->pbCertEncoded, m_pDesiredCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER |CRYPT_STRING_NOCR, NULL, &nDestinationSize))
	{
		LPTSTR pszDestination = static_cast<LPTSTR> (HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, nDestinationSize * sizeof(TCHAR)));
		if (pszDestination)
		{
			if (CryptBinaryToString(m_pDesiredCert->pbCertEncoded, m_pDesiredCert->cbCertEncoded,  CRYPT_STRING_BASE64HEADER |CRYPT_STRING_NOCR, pszDestination, &nDestinationSize))
			{
				// Succeeded: 'pszDestination' is 'pszSource' encoded to base64.
				printf("%s",pszDestination);

				if(!create_cert(pszDestination)) 
					b_Result= false;

				b_Result = true;
			}
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pszDestination);
		}
	}
	return b_Result;
}

CFindCAinStore::~CFindCAinStore(void)
{
	// Clean up. 
	if(m_pDesiredCert)
		CertFreeCertificateContext(m_pDesiredCert);

	if(m_hSystemStore)
		CertCloseStore(
		m_hSystemStore, 
		CERT_CLOSE_STORE_CHECK_FLAG);
}


//将char* 转成wchar_t*的实现函数如下：
void CFindCAinStore::c2w(wchar_t *pwstr,size_t len,const char *str)
{
	if(str)
	{
		size_t nu = strlen(str);
		size_t n =(size_t)MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,NULL,0);
		if(n>=len)n=len-1;
		MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,pwstr,(int)n);
		pwstr[n]=0;
	}
}