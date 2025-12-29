use tower_lsp::lsp_types::SemanticTokenType;


pub const SEMANTIC_TOKENS: &[SemanticTokenType] = &[
    SemanticTokenType::DECORATOR,
    SemanticTokenType::PARAMETER,
    SemanticTokenType::MACRO,
    SemanticTokenType::TYPE,
    SemanticTokenType::COMMENT,
    SemanticTokenType::KEYWORD,
    SemanticTokenType::PROPERTY,
    SemanticTokenType::NAMESPACE,
    SemanticTokenType::VARIABLE,
    SemanticTokenType::STRING,
    SemanticTokenType::NUMBER,
    SemanticTokenType::FUNCTION,
    SemanticTokenType::OPERATOR
];

pub const OMACROS: [&'static str; 13] = [
    "M_E",
    "MLOG2E",
    "M_LOG10E",
    "M_LN2",
    "M_LN10",
    "M_PI",
    "M_PI_2",
    "M_PI_4",
    "M_1_PI",
    "M_2_PI",
    "M_2_SQRTPI",
    "M_SQRT2",
    "M_SQRT1_2"
];

pub const OPEN_BLOCKS: [&'static str; 14] = [
    "instrument_definition",
    "udo_definition_legacy",
    "udo_definition_modern",
    "internal_code_block",
    "if_statement",
    "else_block",
    "elseif_block",
    "switch_statement",
    "case_block",
    "default_block",
    "while_loop",
    "until_loop",
    "for_loop" ,
    "score_nestable_loop"
];

pub const CLOSE_BLOCKS: [&'static str; 16] = [
    "kw_endin",
    "kw_endop",
    "kw_endif",
    "kw_fi",
    "kw_od",
    "kw_switch_end",
    "kw_else",
    "kw_elseif",
    "kw_case_key",
    "kw_default_key",
    "endsw",
    "else_block",
    "elseif_block",
    "case_header",
    "default_header",
    "}"
];
