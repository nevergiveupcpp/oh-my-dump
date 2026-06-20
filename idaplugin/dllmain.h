#ifndef NGU_OMD_DLLMAIN_H
#define NGU_OMD_DLLMAIN_H

#include <cstddef>

#include <idp.hpp>

namespace omd {
    class plugin final : public plugmod_t {
    public:
        bool idaapi run(std::size_t arg) override;
    };
    plugmod_t* idaapi init();
} // namespace omd

#endif // NGU_OMD_DLLMAIN_H
