#include "FsBlobView.h"

using cpputils::Data;

namespace cryfs {
    constexpr uint16_t FsBlobView::FORMAT_VERSION_HEADER;
    constexpr unsigned int FsBlobView::HEADER_SIZE;

#ifndef CRYFS_NO_COMPATIBILITY
    void FsBlobView::migrate(blobstore::Blob *blob, const blockstore::Key &parentKey) {
        constexpr unsigned int OLD_HEADER_SIZE = sizeof(FORMAT_VERSION_HEADER) + sizeof(uint8_t);

        ASSERT(FsBlobView::getFormatVersionHeader(*blob) == 0, "Block already migrated");
        // Resize blob and move data back
        cpputils::Data data = blob->readAll();
        blob->resize(blob->size() + blockstore::Key::BINARY_LENGTH);
        blob->write(data.dataOffset(OLD_HEADER_SIZE), HEADER_SIZE, data.size() - OLD_HEADER_SIZE);
        // Write parent pointer
        blob->write(parentKey.data().data(), sizeof(FORMAT_VERSION_HEADER) + sizeof(uint8_t), blockstore::Key::BINARY_LENGTH);
        // Update format version number
        blob->write(&FORMAT_VERSION_HEADER, 0, sizeof(FORMAT_VERSION_HEADER));
    }
#endif
}
