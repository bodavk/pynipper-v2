# Plan: CheckPoint FW1 Parser Implementation

## Research Analysis
- **File Format (`*.C`, `*.fws`)**: These are structured, nested files resembling Lisp or JSON with parentheses (`(...)`).
- **Parsing Strategy**: A simple line-by-line parser will be insufficient due to the nested nature.
- **Approach**: 
    1. Develop a recursive-descent parser or a parser that treats these as nested data structures to convert into a more usable Python dictionary format.
    2. Focus on extracting key objects (`:netobj`, `:services`, `:rulebases`).

## Implementation Plan
1. [ ] **Implement `CheckPointParser`**: Create a helper class in `src/devices/checkpoint/parser.py` that handles the nested parsing of `*.C` files.
2. [ ] **Update `CheckPointFW1Parser`**: Integrate this helper to populate the parser's state with extracted objects/rules.
3. [ ] **Develop Plugins**: Create CheckPoint-specific plugins based on the extracted structure.

## Status
- [x] Research format structure (done via reference file analysis).
- [ ] Define parsing logic (In progress).
- [ ] Implement parser helper.
- [ ] Implement plugins.
- [ ] Validate with example data.
