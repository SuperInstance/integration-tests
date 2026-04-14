# integration-tests

## Description
Integration tests for the **Cocapn Fleet** (https://github.com/SuperInstance).  
Ensures that agents, protocols, and fleet components work together correctly.

## Usage
```bash
# Install test dependencies (if any)
pip install -r requirements.txt   # optional

# Run all integration tests
python -m unittest discover -s .
```

## Related
- **Cocapn Fleet**: https://github.com/SuperInstance  
- **GitHub Actions** configuration: `.github/`  

---  

**Repository contents**  
- `test_cross_agent.py`  
- `test_fleet_protocol_integration.py`  
- `test_git_agent_integration.py`  
- `test_keeper_integration.py`  
- `test_self_contained_fleet.py`  
- `test_trust_capability_integration.py`  
- `test_workshop_recipe_integration.py`  
- `LICENSE`  
- `.github/` (CI workflows)  