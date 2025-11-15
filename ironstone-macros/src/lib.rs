use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Lit, Meta, Variant};

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

#[proc_macro_derive(EnumTextType)]
pub fn enum_text_type_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);
    // Get the name of the struct we're deriving for (e.g., "AccountRow")
    let name = &ast.ident;

    // Extract the enum variants from the AST
    let variants = if let syn::Data::Enum(data) = ast.data {
        data.variants
    } else {
        // This macro only works on enums, so we'll panic if it's not an enum.
        unimplemented!("EnumTextType can only be used on enums");
    };

    // --- Logic to generate match arms for Display and FromStr ---

    // A helper function to find the `#[serde(rename = "...")]` string
    fn get_string_repr(variant: &Variant) -> String {
        for attr in &variant.attrs {
            if attr.path().is_ident("serde") {
                if let Meta::List(meta_list) = &attr.meta {
                    if let Ok(expr) = meta_list.parse_args::<syn::MetaNameValue>() {
                        if expr.path.is_ident("rename") {
                            if let syn::Expr::Lit(expr_lit) = expr.value {
                                if let Lit::Str(lit_str) = expr_lit.lit {
                                    return lit_str.value();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Default to the lowercase version of the variant name
        variant.ident.to_string().to_lowercase()
    }

    // Create the match arms for the `Display` implementation
    let display_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let string_repr = get_string_repr(variant);
        quote! { Self::#variant_ident => write!(f, #string_repr) }
    });

    // Create the match arms for the `FromStr` implementation
    let from_str_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let string_repr = get_string_repr(variant);
        quote! { #string_repr => Ok(Self::#variant_ident) }
    });

    // Generate the implementation of the HasId trait
    let gen = quote! {
      // --- Display Implementation ---
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(#display_arms),*
                }
            }
        }

        // This now adds the necessary trailing comma
        impl std::str::FromStr for #name {
            // Use a generic boxed error to avoid defining a new struct.
            type Err = Box<dyn std::error::Error + Send + Sync + 'static>;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
               match s {
                    #(#from_str_arms,)*

                    // For the wildcard case, create the error from a formatted string.
                    // The `.into()` at the end converts the String into the Box<dyn Error>.
                    _ => Err(format!("Invalid variant `{}` for enum `{}`", s, stringify!(#name)).into()),
                }
            }
        }

            // --- DECODE (From database TEXT to Rust Enum) ---
        impl<'r> sqlx::decode::Decode<'r, sqlx::Postgres> for #name {
            fn decode(value: sqlx::postgres::PgValueRef<'r>) -> std::result::Result<Self, sqlx::error::BoxDynError> {
                let value_str = <&str as sqlx::decode::Decode<sqlx::Postgres>>::decode(value)?;
                Ok(#name::from_str(value_str)?)
            }
        }

        // --- ENCODE (From Rust Enum to database TEXT) ---
        impl<'q> sqlx::encode::Encode<'q, sqlx::Postgres> for #name {
            fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> std::result::Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                let s = self.to_string();
                <&str as sqlx::encode::Encode<sqlx::Postgres>>::encode(&s, buf)
            }
        }

        impl sqlx::Type<sqlx::Postgres> for #name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                // This tells sqlx that our `$ty` enum corresponds to the `TEXT` type in PostgreSQL.
                sqlx::postgres::PgTypeInfo::with_name("TEXT")
            }
        }
    };

    // Return the generated code as a TokenStream
    gen.into()
}

#[proc_macro_derive(HasActiveFilter)]
pub fn has_active_filter_derive(input: TokenStream) -> TokenStream {
    // 1. Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    // 2. Extract fields (assuming it's a struct with named fields)
    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => panic!("HasActiveFilter can only be derived for structs with named fields."),
        },
        _ => panic!("HasActiveFilter can only be derived for structs."),
    };

    // 3. Generate the OR'd checks for each field.
    // The macro iterates over the fields and creates tokens like: self.field1.is_some() || self.field2.is_some()
    let checks = fields
        .iter()
        .map(|f| {
            let field_name = &f.ident;
            quote! {
                self.#field_name.is_some()
            }
        })
        .collect::<Vec<_>>();

    // 4. Combine into the final impl block
    let expanded = quote! {
        // You need to ensure the trait path is correct for your project
        impl HasActiveFilter for #name {
            fn has_active_filter(&self) -> bool {
                // Combine all checks with '||'
                #(#checks)||*
            }
        }
    };

    TokenStream::from(expanded)
}
