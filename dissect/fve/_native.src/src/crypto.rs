use pyo3::prelude::*;

mod argon2;

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "crypto")?;
    argon2::create_submodule(&submodule)?;
    m.add_submodule(&submodule)
}
