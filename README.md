# integration-tests

## Description
Integration tests for the **Cocapn Fleet** (https://github.com/SuperInstance).  
The suite validates cross‑agent communication, fleet protocol handling, Git agent operations, keeper interactions, self‑contained fleet behavior, trust capability enforcement, and workshop recipe execution.

## Usage
```bash
# Install test dependencies (if any)
pip install -r requirements.txt   # optional

# Run all tests
python -m unittest discover -s .

# Run a specific test file
python -m unittest test_fleet_protocol_integration.py
```

## Related
- **Cocapn Fleet**: https://github.com/SuperInstance/cocapn-fleet  
- **GitHub Actions workflows**: `.github/` directory in this repo  

---  

*License:* See `LICENSE` file.