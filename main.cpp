#include <vcl.h>

#include <stdlib.h>
#include <stdio.h>
#include "FindCAinStore.h"
int main()
{
     LPCSTR lpszCertSubject = (LPCSTR) "VeriSign Class 3 Public Primary Certification Authority - G5";

	CFindCAinStore caStore;
	if(!caStore.find_Cert(lpszCertSubject))
		exit(-1);

	if(!caStore.createCAfile_base64())
		exit(-1);	

	system("pause");
	return 0;
}


