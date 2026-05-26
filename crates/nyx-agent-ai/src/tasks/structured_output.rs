use serde_json::Value;

pub(crate) fn json_values_from_text(text: &str) -> Vec<Value> {
    let mut values = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let Some((relative_start, ch)) =
            text[offset..].char_indices().find(|(_, ch)| matches!(ch, '{' | '['))
        else {
            break;
        };
        let start = offset + relative_start;
        let Some(end) = json_slice_end(text, start) else {
            offset = start + ch.len_utf8();
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(&text[start..end]) {
            values.push(value);
            offset = end;
        } else {
            offset = start + ch.len_utf8();
        }
    }
    values
}

fn json_slice_end(text: &str, start: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' => {
                if stack.pop() != Some(ch) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(start + idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub(crate) fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pretty_json_from_markdown_fence() {
        let text = "done\n```json\n{\n  \"profile\": {\n    \"target_urls\": [\"http://127.0.0.1:3000\"]\n  }\n}\n```";
        let values = json_values_from_text(text);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["profile"]["target_urls"][0], "http://127.0.0.1:3000");
    }

    #[test]
    fn ignores_braces_inside_strings() {
        let text = r#"{"summary":"kept { brace } in a string","warnings":[]}"#;
        let values = json_values_from_text(text);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["summary"], "kept { brace } in a string");
    }
}
