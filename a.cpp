
bool GetAdapterMAC(
    const char* pcapName,
    std::array<unsigned char, 6>& mac
) {
    ULONG bufferSize = 15000;
    std::vector<unsigned char> buffer(bufferSize);

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    DWORD result = GetAdaptersAddresses(
        AF_UNSPEC,
        flags,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
        &bufferSize
    );

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        result = GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &bufferSize
        );
    }

    if (result != NO_ERROR)
        return false;

    // Convert Npcap name into Windows adapter GUID.
    std::string name(pcapName);
    size_t pos = name.find('{');

    if (pos == std::string::npos)
        return false;

    std::string guid = name.substr(pos);

    auto* adapter =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    for (; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->AdapterName == nullptr)
            continue;

        if (_stricmp(adapter->AdapterName, guid.c_str()) == 0) {
            if (adapter->PhysicalAddressLength != 6)
                return false;

            std::memcpy(
                mac.data(),
                adapter->PhysicalAddress,
                6
            );

            return true;
        }
    }

    return false;
}
