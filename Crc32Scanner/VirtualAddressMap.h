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

    void InsertNodeAtLastPosition(vmap* headnode, long long startaddress, long long endaddress, long long reagionsize );

};

