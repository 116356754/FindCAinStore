#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

class CFindCAinStore
{
public:
	CFindCAinStore(const char *cName="ROOT");
	~CFindCAinStore(void);
	bool find_Cert(const char* lpszCertSubject);
	bool createCAfile_base64();
private:
	void c2w(wchar_t *pwstr,size_t len,const char *str);
	bool create_cert(LPTSTR pszDestination);
private:
	HCERTSTORE  m_hSystemStore;
	PCCERT_CONTEXT  m_pDesiredCert;
};

