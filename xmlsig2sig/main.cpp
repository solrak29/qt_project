//
// File main.cpp
//
// Main drive of the code that will check for two file names.
// The first argument is the file that will be read to convert to the next file.
// The second argument is the file that will be created with converted from first file.
//
// Author: carlos.negron.nyc@gmail.com 
//

#include <iostream>
#include <string>
#include "xmlsig2sig.h"

using namespace std;

void usage() {
    cout << "Error Incorrect Arguments" << endl;
    cout << "Usage: xml2sigxml <old filename> < new filename>" << endl;
}


int main(int argc, char** argv ) {
    // keep it simple and just see that we have the right args
    if (argc > 2 ) {
        string fileOld = argv[1];
        string fileNew = argv[2];
        cout << "Processing old file => " << fileOld << endl;
        cout << "Processing new file => " << fileNew << endl;
        processFiles(fileOld, fileNew);
        //char* path_exec = "C:\\Users\\USER\\Downloads\\U_STIGViewer_2-11_Win64\\bin\\STIGViewer.bat test.ckl";
        //cout << path_exec << endl;
        //system(path_exec);
        cout << "finished" << endl;
    } else {
        usage();
    }
    return 0;
}
