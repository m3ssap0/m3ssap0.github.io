---
layout: post
title: "Secrets leaks prevention with pre-commit hooks and Gitleaks"
date: 2023-09-29 08:49
---

## Problem Statement
Committing in a repository confidential material like passwords, API secrets, private keys is a **severe security issue** and could have **serious consequences**.

The nature of version control systems is to track all changes performed over time on a specific code base. For this reason, simply removing the leaked material with a subsequential commit is usually not sufficient: a **malicious actor could access to the history** and retrieve the leaked secret, using it to move laterally in the system.

There are [techniques to clean repository history](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository#purging-a-file-from-your-repositorys-history) and you can always invalidate a leaked secret, but this could be time consuming and leaks could happen accidentally, without you noticing it.

## Table of Contents
* [Problem Statement](#problem-statement)
* [Possible Solution: Gitleaks and pre-commit hooks](#possible-solution-gitleaks-and-pre-commit-hooks)
* [Custom Gitleaks rules file](#custom-gitleaks-rules-file)
* [Extra Mile: continuous automatic security checks and secrets management](#extra-mile-continuous-automatic-security-checks-and-secrets-management)
* [References](#references)

![www.craiyon.com - Preventing secrets leaks](images/craiyon_103602_Preventing_secrets_leaks.png)

## Possible Solution: Gitleaks and pre-commit hooks

Luckily for us, there are some tools that can be used to automate leaks detection, blocking a commit operation *before* the leak happens.

The tool that can help is ***Gitleaks*** ([reference](https://gitleaks.io/)/[repository](https://github.com/gitleaks/gitleaks)).

> Gitleaks is a SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an easy-to-use, all-in-one solution for detecting secrets, past or present, in your code.

Gitleaks, alone, is not able to scan each commit in real time, but it supports the integration with ***pre-commit*** hooks. With pre-commit hooks, secrets will be detected before the effective commit, preventing the leak at the beginning.

You can use [git native pre-commit hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks).
            
1. Create a folder where to store global hooks, for example: `/home/<your_user>/gitconfig/hooks`.
2. Create a file with **exactly** the name `pre-commit` in folder you just created and paste a code like the following (customized starting from [this](https://github.com/gitleaks/gitleaks/blob/master/scripts/pre-commit.py)). Be sure to add the path to your custom Gitleaks rules if needed!
    ```python
    #!/usr/bin/env python3
    """Helper script to be used as a pre-commit hook."""
    import os
    import sys
    import subprocess

    def gitleaksEnabled():
        """Determine if the pre-commit hook for gitleaks is enabled."""
        out = subprocess.getoutput("git config --bool hooks.gitleaks")
        if out == "false":
            return False
        return True

    if gitleaksEnabled():
        exitCode = os.WEXITSTATUS(os.system('gitleaks protect -c <path_to_custom_Gitleaks_rules> -v --staged --redact'))
        if exitCode == 1:
            print('''Warning: gitleaks has detected sensitive information in your changes.
    To disable the gitleaks precommit hook run the following command:

        git config hooks.gitleaks false
    ''')
            sys.exit(1)
    else:
        print('gitleaks precommit disabled\
        (enable with `git config hooks.gitleaks true`)')
    ```
3. Make the file executable.
4. Edit your global git config file (usually `.gitconfig` in your home) to add the following lines.
    ```
    [core]
        hooksPath = /home/<your_user>/gitconfig/hooks
    [hooks]
        gitleaks = true
    ```
    
## Custom Gitleaks rules file

You would probably need some custom rules to detect custom secrets. When creating custom rules files, you could like to extend default rules provided by Gitleaks. An example of `custom-config.toml` to extend default rules is the following.

```toml
# Your custom Gitleaks configuration file.
title = "Your custom Gitleaks rules"

# Extending default rules here.
[extend]
useDefault = true


[[rules]]
# Put your custom rules here.
```

## Extra Mile: continuous automatic security checks and secrets management

In an enterprise scenario, the above solution is not sufficient to be completely safe.

Evaluate the possibility to include tools like Gitleaks in your Software Development LifeCycle (SDLC), for example integrating them in your Continuous Integration / Continuous Delivery (CI/CD) pipelines.

Also consider the adoption of secrets management tools, like [*HashiCorp Vault*](https://www.vaultproject.io/) or the alternative of your cloud provider. Software engineers will have a concrete solution to their problem and you will effectively manage the secrets ecosystem.

## References
* [Gitleaks - Home page](https://gitleaks.io/)
* [Gitleaks - Repository](https://github.com/gitleaks/gitleaks)
* [GitHub - Removing sensitive data from a repository - Purging a file from your repository's history](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository#purging-a-file-from-your-repositorys-history)
* [git - Customizing Git - Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
* [HashiCorp Vault - Home page](https://www.vaultproject.io/)
