use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(HasId)]
pub fn has_id_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // Get the name of the struct we're deriving for (e.g., "AccountRow")
    let name = &ast.ident;

    // Find the type of the `id` field
    let id_type = match &ast.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(fields) => {
                // Look for a field with the identifier "id"
                let id_field = fields
                    .named
                    .iter()
                    .find(|f| f.ident.as_ref().unwrap() == "id");
                match id_field {
                    Some(field) => &field.ty, // Get the type of the field
                    None => panic!("Struct must have a field named `id` to derive `HasId`"),
                }
            }
            _ => panic!("`HasId` can only be derived for structs with named fields"),
        },
        _ => panic!("`HasId` can only be derived for structs"),
    };

    // Generate the implementation of the HasId trait
    let gen = quote! {
        impl HasId for #name {
            type Id = #id_type;
        }
    };

    // Return the generated code as a TokenStream
    gen.into()
}
