#include <sstream>
#include <vector>
#include <string.h>
#include <fstream>
#include <iostream>

using namespace std;

int main (int argc, char** argv){

    //open file to read
    ifstream ifs(argv[1]);
    if (!ifs){
        //file not found
        cout << "File \"" << argv[1] << "\" not found!" << endl;
        return -1;
    }


    //get argument parameter for N messages
    int n;
    string line;
    getline(ifs,line,'\n');

    n = stoi(line);
    
    vector<string> messages(n);
    for(int i = 0; i < n; i++){
        getline(ifs,line,'\n');
        messages[i] = line;
    }

}