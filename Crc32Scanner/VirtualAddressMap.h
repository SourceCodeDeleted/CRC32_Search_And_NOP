#pragma once
class VirtualAddressMap
{

public:
    struct vmap {
        long long StartAddress;
        long long EndAddress;
        long long RegionSize;
        struct vmap* Next;
    };

    void printList(vmap* headnode);
    int  GetCountOfBlocks(vmap* headnode);
    long long ConvertStrAddressToInt(char* strNumber);
    void InsertNodeAtLastPosition(vmap** headnode, long long startaddress, long long endaddress, long long regionsize);
    void PrepareDeleteBlocks(std::vector<std::string> ignoreBlockAddresses);
    void DeleteNodeByKey(vmap** headnode, long long key);
    vmap ReturnNextNode(vmap* headnode);

};

