#include "includes.h"

void VirtualAddressMap::InsertNodeAtLastPosition(vmap** headnode, long long startaddress, long long endaddress, long long regionsize)
{

    // 1. allocate node
    vmap* new_node = new vmap();

    // Used in step 5
    vmap* last = *headnode;

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
    if (*headnode == nullptr)
    {
        *headnode = new_node;
        return;
    }

    // 5. Else traverse till the last node
    while (last->Next != nullptr)
        last = last->Next;

    // 6. Change the next of last node
    last->Next = new_node;
    return;
}

long long VirtualAddressMap::ConvertStrAddressToInt( char * strNumber) 
{
     long long number = strtoll(strNumber, NULL, 0);
     return number;
}


void VirtualAddressMap::DeleteNodeByKey(vmap** headnode, long long key) 
{
    // Given a reference (pointer to pointer)
    // to the head of a list and a key, deletes
    // the first occurrence of key in linked list

    // Store head node
        vmap* temp = *headnode;
        vmap* prev = NULL;

        
        // If head node itself holds
        // the key to be deleted
        if (temp != NULL && temp->StartAddress == key)
        {
            
            std::cout << "[+] Removing Block \t" << std::hex << key << " From Search..." << std::endl;
            *headnode = temp->Next; // Changed head
            delete temp;            // free old head
            return;
        }

        // Else Search for the key to be deleted,
        // keep track of the previous node as we
        // need to change 'prev->next' */
        else
        {
            
            while (temp != NULL && temp->StartAddress != key)
            {
//                
                prev = temp;
                temp = temp->Next;
            }

            // If key was not present in linked list
            if (temp == NULL)
                return;

            std::cout << "[+] Removing Block " << std::hex << key << " From Search..." << std::endl;
            // Unlink the node from linked list
            prev->Next = temp->Next;

            // Free memory
            delete temp;
        }
}




void VirtualAddressMap::printList(vmap* headnode)
{
    std::cout << "Memory Blocks Map:" << std::endl;

    while (headnode != NULL)
    {
        std::cout << "Start Addr: \t" << std::hex << headnode->StartAddress << "\t EndAddress \t"  << std::hex << headnode->EndAddress << "\t BlockSize \t" << headnode->RegionSize << std::endl;
        headnode = headnode->Next;
    }
}


VirtualAddressMap::vmap VirtualAddressMap::ReturnNextNode(vmap* headnode) {
    headnode = headnode->Next;

    return *headnode;
}

// Not needed, because I can continue until headnode -> nullptr
int VirtualAddressMap::GetCountOfBlocks(vmap* headnode)
{
    std::cout << "Calculating Total Blocks: " << std::endl;
    int count = 0;

    while (headnode != NULL)
    {
        count++;
        headnode = headnode->Next;
    }

    return count;
}