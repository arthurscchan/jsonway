// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

extern crate jsonway;

use libfuzzer_sys::fuzz_target;
use jsonway::{ObjectBuilder, ArrayBuilder, Serializer};
use serde_json::Value;

// Define Fuzz object and enum catory for fuzzing
#[derive(Debug)]
enum Category {
    Alpha,
    Beta,
    Gamma,
    Delta,
}

struct Fuzz {
    name: String,
    category: Category,
}

struct FuzzSerializer<'a> {
    fuzz: &'a Fuzz,
}

impl<'a> Serializer for FuzzSerializer<'a> {
    fn root(&self) -> Option<&str> {
        Some("fuzz_object")
    }

    fn build(&self, json: &mut ObjectBuilder) {
        json.set("name", self.fuzz.name.to_string());
        json.set("category", format!("{:?}", self.fuzz.category));
    }
}


// Generate sample fuzz objects for fuzzing
fn generate_fuzz_objects() -> Vec<Fuzz> {
    vec![
        Fuzz { name: "FuzzOne".to_string(), category: Category::Alpha },
        Fuzz { name: "FuzzTwo".to_string(), category: Category::Beta },
        Fuzz { name: "FuzzThree".to_string(), category: Category::Gamma },
        Fuzz { name: "FuzzFour".to_string(), category: Category::Delta },
        Fuzz { name: "FuzzFive".to_string(), category: Category::Alpha },
        Fuzz { name: "FuzzSix".to_string(), category: Category::Beta },
        Fuzz { name: "FuzzSeven".to_string(), category: Category::Gamma },
        Fuzz { name: "FuzzEight".to_string(), category: Category::Delta },
    ]
}

// Function to extract a random value from fuzzing data with different type.
fn extract_value(data: &[u8], index: &mut usize) -> Value {
    if *index >= data.len() {
        return Value::Null;
    }

    let choice = data[*index] % 7;
    *index += 1;

    match choice {
        0 => Value::Null,
        1 => Value::Bool(data[*index % data.len()] % 2 == 0),
        2 => Value::Number(serde_json::Number::from(data[*index % data.len()] as i64)),
        3 => Value::String(format!("string_{}", *index)),
        4 => Value::Array(vec![Value::String(format!("array_value_{}", *index))]),
        5 => Value::Object(serde_json::Map::new()),
        _ => Value::Array(Vec::new()),
    }
}

// Functions for generating random data and nested objects / arrays
fn generate_random_number(data: &[u8], index: &mut usize, upper_bound: usize) -> usize {
    *index += 1;
    if *index < data.len() {
        data[*index] as usize % upper_bound
    } else { 0 }
}

fn fuzz_deeply_nested_object(data: &[u8], index: &mut usize, depth: usize) -> Value {
    if depth == 0 || *index >= data.len() {
        return Value::Null;
    }

    let mut obj = serde_json::Map::new();
    for _ in 0..generate_random_number(data, index, 5) {
        let key = format!("key_{}", *index);
        let val = if generate_random_number(data, index, 10) % 2 == 0 {
            fuzz_deeply_nested_object(data, index, depth - 1)
        } else {
            extract_value(data, index)
        };
        obj.insert(key, val);
    }

    Value::Object(obj)
}

fn fuzz_deeply_nested_array(data: &[u8], index: &mut usize, depth: usize) -> Value {
    if depth == 0 || *index >= data.len() {
        return Value::Array(Vec::new());
    }

    let mut arr = Vec::new();
    for _ in 0..generate_random_number(data, index, 5) {
        let val = if generate_random_number(data, index, 10) % 2 == 0 {
            fuzz_deeply_nested_array(data, index, depth - 1)
        } else {
            extract_value(data, index)
        };
        arr.push(val);
    }

    Value::Array(arr)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let mut index = 0;
    let fuzz_list = generate_fuzz_objects();
    let mut object_builder = ObjectBuilder::new();
    let mut array_builder = ArrayBuilder::new();

    let fuzz_target_choice = data[0] % 15;

    match fuzz_target_choice {
        0 => {
            jsonway::object(|json| {
                json.set("key1", extract_value(data, &mut index));
                json.object("nested_object", |json| {
                    json.set("inner_key1", extract_value(data, &mut index));
                    json.set("inner_key2", fuzz_deeply_nested_object(data, &mut index, 5));
                });
            }).unwrap();
        },
        1 => {
            jsonway::array(|arr| {
                arr.push(extract_value(data, &mut index));
                arr.array(|arr| {
                    arr.push(extract_value(data, &mut index));
                    arr.push_json(fuzz_deeply_nested_array(data, &mut index, 5));
                });
            }).unwrap();
        },
        2 => {
            jsonway::object(|json| {
                json.object("deeply_nested_object", |json| {
                    json.array("deep_array", |json| {
                        for _ in 0..generate_random_number(data, &mut index, 5) {
                            json.push(fuzz_deeply_nested_object(data, &mut index, 5));
                        }
                    });
                });
            }).unwrap();
        },
        3 => {
            for fuzz in &fuzz_list {
                let mut fuzz_serializer = FuzzSerializer { fuzz };
                fuzz_serializer.serialize(data.len() > 0 && data[index % data.len()] % 2 == 0);
            }
        },
        4 => {
            array_builder.objects(fuzz_list.iter(), |fuzz, json| {
                json.set("fuzz_key", fuzz.name.to_string());
                json.set("fuzz_category", format!("{:?}", fuzz.category));
            });
            array_builder.unwrap();
        },
        5 => {
            object_builder.object("object_key", |json| {
                json.set("name", fuzz_list[0].name.to_string());
                json.set("category", format!("{:?}", fuzz_list[0].category));
            });
            object_builder.unwrap();
        },
        6 => {
            array_builder.push(fuzz_deeply_nested_array(data, &mut index, 5));
            object_builder.set("object_key", fuzz_deeply_nested_object(data, &mut index, 5));
            array_builder.unwrap();
            object_builder.unwrap();
        },
        7 => {
            jsonway::object(|_json| {}).unwrap();
            jsonway::array(|_arr| {}).unwrap();
        },
        8 => {
            let large = Value::String("large_value".repeat(100));
            let small = Value::String("small_value".to_string());
            object_builder.set("large_data", large);
            object_builder.set("small_data", small);
            object_builder.unwrap();
        },
        9 => {
            array_builder.push(Value::Array(Vec::new()));
            array_builder.push(Value::Array(vec![Value::String("full_array_value".to_string())]));
            array_builder.unwrap();
        },
        10 => {
            jsonway::object(|json| {
                json.set("null_key", Value::Null);
                json.set("empty_string", Value::String("".to_string()));
                json.set("large_string", Value::String("x".repeat(1000)));
            }).unwrap();
        },
        11 => {
            jsonway::object(|json| {
                json.set("duplicate_key", "value1");
                json.set("duplicate_key", "value2");
            }).unwrap();
        },
        12 => {
            jsonway::array(|arr| {
                for _ in 0..generate_random_number(data, &mut index, 100) {
                    arr.push(extract_value(data, &mut index));
                }
            }).unwrap();
        },
        13 => {
            let key = format!("key_{}", data[index % data.len()]);
            jsonway::object(|json| {
                json.set(key, extract_value(data, &mut index));
            }).unwrap();
        },
        14 => {
            jsonway::array(|arr| {
                for _ in 0..generate_random_number(data, &mut index, 5) {
                    arr.push(fuzz_deeply_nested_object(data, &mut index, 5));
                }
            }).unwrap();
        },
        _ => {}
    }
});
