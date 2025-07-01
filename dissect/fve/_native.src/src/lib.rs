use pyo3::prelude::*;

mod crypto;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crypto::create_submodule(m)?;
    Ok(())
}
