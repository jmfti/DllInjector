#include "cInjector.h"


int howto()
{

	cout << "****************************************************" << endl;
	cout << "************** Dll Injector by jmf ****************" << endl;
	cout << "****************************************************" << endl;
	cout << endl << endl;

	cout << "use example : injector process.exe name.dll [Redirect OR RemoteThread]" << endl;
	return 1;

}

int main(int argc, char* argv[])
{

	if (argc <= 3) return howto();
	DWORD pid = 0;
	pid = atoi(argv[1]);
	Injector *t;
	if (pid) t = new Injector(pid, argv[2]);
	else	t = new Injector(argv[1], argv[2]);
	if (!t) return 1;
	string method = argv[3];
	DataInj *m = NULL;
	try{
	t->Init();
	}
	catch (excpt &e) { cout << e.what() << endl; }

	try {

		if (method.find("Remote") != method.npos) {

			if (t->RemoteThread())
			{
				cout << "successfuly injected" << endl;
				cout << "thread : [" << t->GetThreadAddress() << "]" <<endl;
				m = t->GetData();
				cout << *m << endl;
				cout << "press ENTER to continue" << endl;
				cin.get();
				cout << t->FreeRemoteThread() << endl;
				t->CleanUp();
				delete m;
			}

		}

		if (method.find("Redirect") != method.npos) 
		{
			if (t->ThreadRedirect())
			{

				cout << "Successfuly injected" << endl;
				m = t->GetData();
				cout << *m << endl;
				cout << "press ENTER to continue" << endl;
				cin.get();
				t->FreeRedirect();

			}

			else cout << "false" << endl;

		}

	}
	catch (excpt &e) { cout << e.what(); };
	return 0;

}