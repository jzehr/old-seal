
#include <iostream>
#include <list>
#include <vector>


using namespace std;

int main()
{

    int dogs[10] = {1,2,3,4,5,6,7,8,9,10};
    int cats[10] = {1,2,13,4,15,6,7,8,9,20};
    std::vector<int> my_list;

    //cout << dogs[3] << endl;

    for(int x = 0; x<= 9; x++){
        //cout << "position:" << x+1 << " " << dogs[x] << " --------  "  << cats[x] << endl;
        if (dogs[x] != cats[x]){
            //cout << dogs[x] << " --------  " << cats[x] << endl;
            my_list.push_back(1);
        }
    }

    cout << "the total number of differences is: --> " << my_list.size() << endl;
    return 0;
}


