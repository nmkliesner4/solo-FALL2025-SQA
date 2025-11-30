Github link: https://github.com/nmkliesner4/solo-FALL2025-SQA

## Activities Performed

First, I created a lightweight Python fuzzing harness (fuzz.py) that scans a target directory (default: MLForensics/) for Python functions and class methods, randomly selects up to five, and repeatedly calls them with randomly generated arguments. Each call runs in a separate process with a timeout to prevent hangs. Crashes, exceptions, and timeouts are logged to fuzz_results.log. It supports optional NumPy inputs, basic type-aware argument generation, safe class instantiation, and CLI options for directory, iterations, timeout, seed, and listing discovered targets.

Next, I integrated forensics using logging statements by modifying the following 5 methods:

	MLForensics/MLForensics-farzana/FAME-ML/lint_engine.py::getDataLoadCount
	MLForensics/MLForensics-farzana/FAME-ML/lint_engine.py::getModelLabelCount
	MLForensics/MLForensics-farzana/FAME-ML/lint_engine.py::getEnvironmentCount
	MLForensics/MLForensics-farzana/empirical/frequency.py::reportProportion
	MLForensics/MLForensics-farzana/empirical/frequency.py::reportEventDensity


Finally, I integrated fuzz.py into the CI/CD pipeline by creating a github action that runs the file and saves the output log as an artifact. An example artifact can be found in the github repo under “fuzz_results.log”



## Lessons Learned

Through this project, I learned how to design and implement a lightweight fuzzing harness for a large repository. I strengthened my understanding of static analysis, dynamic testing, and how fuzzing can uncover unexpected failure modes.

By adding detailed logging instrumentation to several MLForensics methods, I learned how to integrate software forensics, how to capture useful runtime information, and how small code changes can improve traceability and debugging.


Finally, by incorporating the fuzzing tool into a CI/CD pipeline using GitHub Actions, I gained experience with automated testing workflows, artifact storage, and continuous quality assurance. This reinforced how automated fuzzing can be used as part of a real-world software engineering and DevOps process.
