#ifndef NGU_OMD_INTERNALS_EXPORT_EXPORT_FILTERS_H
#define NGU_OMD_INTERNALS_EXPORT_EXPORT_FILTERS_H

#include <array>
#include <cstddef>
#include <string_view>

namespace omd::export_filters {
    enum class match {
        exact,
        prefix,
    };

    struct rule {
        match match{};
        std::string_view pattern{};
    };

    inline constexpr std::array name_rules{
        rule{match::prefix, "def_"},   /// IDA-generated switch default case label
        rule{match::prefix, "jpt_"},   /// IDA-generated jump table symbol
        rule{match::prefix, "funcs_"}, /// IDA-generated function pointer table
        rule{match::prefix, "loc_"},   /// IDA-generated jump position
        rule{match::prefix, "?"},      /// Mangled C++ symbol
        rule{match::prefix, "j_"},     /// Nullsub
    };

    inline constexpr std::array function_name_rules{
        rule{match::prefix, "??"},  /// Mangled C++ symbol
        rule{match::prefix, "??_"}, /// RTTI / vftable helper
        rule{match::prefix, "?__"}, /// compiler-generated helper function
        rule{match::prefix, "__"},  /// CRT / compiler runtime function
    };

    inline constexpr std::array<rule, 0> declaration_rules{};

    inline constexpr std::array comment_rules{
        // Generic IDA-generated parameter names
        rule{match::exact, "Size"},   /// Generic size parameter
        rule{match::exact, "Src"},    /// Generic source pointer
        rule{match::exact, "Void *"}, /// Unknown pointer type
        rule{match::exact, "int"},    /// Generic integer parameter
        rule{match::exact, "Str"},    /// Generic string parameter
        rule{match::exact, "Str1"},   /// Generic string parameter
        rule{match::exact, "String"}, /// Generic string parameter
        rule{match::exact, "Buf1"},   /// Generic buffer parameter
        rule{match::exact, "Buf2"},   /// Generic buffer parameter
        rule{match::exact, "Block"},  /// Generic memory block parameter

        // Generic container / algorithm names
        rule{match::exact, "Table"},    /// Generic table reference
        rule{match::exact, "Function"}, /// Generic function reference
        rule{match::exact, "Last"},     /// STL-style iterator parameter
        rule{match::exact, "First"},    /// STL-style iterator parameter
        rule{match::exact, "Buffer"},   /// Generic buffer parameter
        rule{match::exact, "MaxCount"}, /// Generic count parameter
        rule{match::exact, "Val"},      /// Generic value parameter
        rule{match::exact, "X"},        /// Generic variable name

        // Generic type names produced by IDA
        rule{match::exact, "bool"},               /// Auto-generated type name
        rule{match::exact, "char"},               /// Auto-generated type name
        rule{match::exact, "void *"},             /// Auto-generated type name
        rule{match::exact, "char *"},             /// Auto-generated type name
        rule{match::exact, "char **"},            /// Auto-generated type name
        rule{match::exact, "wchar_t *"},          /// Auto-generated type name
        rule{match::exact, "unsigned int"},       /// Auto-generated type name
        rule{match::exact, "unsigned __int8 *"},  /// Auto-generated type name
        rule{match::exact, "__int64"},            /// Auto-generated type name
        rule{match::exact, "unsigned __int64"},   /// Auto-generated type name
        rule{match::exact, "unsigned __int64 *"}, /// Auto-generated type name
        rule{match::exact, "this"},               /// C++ this pointer

        // Switch analysis
        rule{match::exact, "switch jump"},                     /// IDA switch analysis comment
        rule{match::exact, "jump table for switch statement"}, /// IDA jump table comment

        // RTTI metadata
        rule{match::exact, "signature"},                   /// RTTI structure field
        rule{match::exact, "Trap to Debugger"},            /// Debug runtime metadata
        rule{match::exact, "attributes"},                  /// RTTI attribute field
        rule{match::exact, "base class attributes"},       /// RTTI base class descriptor
        rule{match::exact, "vftable displacement"},        /// RTTI vftable offset
        rule{match::exact, "member displacement"},         /// RTTI member offset
        rule{match::exact, "displacement within vftable"}, /// RTTI vftable displacement
        rule{match::exact, "type descriptor name"},        /// RTTI type descriptor
        rule{match::exact, "internal runtime reference"},  /// CRT/runtime reference

        // Windows x64 unwind information
        rule{match::prefix, "UWOP_"}, /// x64 unwind opcode

        // EH metadata statistics
        rule{match::prefix, "num_ip2state entries:"}, /// EH IP-to-state entry count
        rule{match::prefix, "num unwind entries:"},   /// EH unwind entry count

        // Switch/jumptable comments
        rule{match::prefix, "switch "},    /// IDA switch analysis comment
        rule{match::prefix, "jumptable "}, /// IDA jump table comment

        // Auto-generated references
        rule{match::prefix, "ea 0x"},         /// Effective address reference
        rule{match::prefix, "reference to "}, /// Auto-generated cross-reference

        // Auto-generated structure field descriptions
        rule{match::prefix, "frame offset of "}, /// Stack frame offset description
        rule{match::prefix, "# of "},            /// Entry count field
        rule{match::prefix, "offset of "},       /// Structure offset description
        rule{match::prefix, "count of "},        /// Count field description
    };
} // namespace omd::export_filters

#endif // NGU_OMD_INTERNALS_EXPORT_EXPORT_FILTERS_H
