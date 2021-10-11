#include "VirtualAddressMap.h"

void VirtualAddressMap::InsertNodeAtLastPosition(vmap* headnode, long long startaddress, long long endaddress, long long regionsize)
{


    // 1. allocate node
    vmap* new_node = new vmap();

    // Used in step 5
    vmap* last = headnode;

    // 2. Put in the data
    new_node->StartAddress = startaddress;
    new_node->EndAddress   = endaddress;
    new_node->RegionSize   = regionsize;

    // 3. This new node is going to be 
    // the last node, so make next of 
    // it as NULL
    new_node->Next = nullptr;

    // 4. If the Linked List is empty,
    // then make the new node as head
    if (headnode == nullptr)
    {
        headnode = new_node;
        return;
    }

    // 5. Else traverse till the last node
    while (last->Next != nullptr)
        last = last->Next;

    // 6. Change the next of last node
    last->Next = new_node;
    return;
}
