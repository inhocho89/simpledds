#include <iostream>
#include <map>

using namespace std;

int main (){
	map<int,int> abc;

	abc[10] = 1;
	abc[20] = 2;
	abc[30] = 3;

	for(map<int,int>::iterator it=abc.begin(); it!=abc.end(); ++it){
		//if (it->first == 20){
		//	abc.erase(it);
		//}
		it->second--;
	}

	for(map<int,int>::iterator it=abc.begin(); it!=abc.end(); ++it){
		cout << it->first << "->" << it->second << endl;
	}

}
