# Working together

## Branches
```
main                      always works, demo-ready, protected (merge only at milestones)
develop                   integration branch; everyone's finished work meets here
feature/c1-<topic>        Component 1 work   e.g. feature/c1-xgboost-calibration
feature/c2-<topic>        Component 2 work
feature/c3-<topic>        Component 3 work   e.g. feature/c3-live-receiver
feature/c4-<topic>        Component 4 work
```

## Daily routine in VS Code (Source Control panel or terminal)
```
git checkout develop
git pull                                  # get the others' latest work
git checkout feature/c3-<topic>           # your branch (first time: git checkout -b feature/c3-<topic>)
git merge develop                         # bring their changes into yours, fix conflicts here
... work, test ...
git add <your folders only>
git commit -m "c3: short clear message"
git push -u origin feature/c3-<topic>
```
Then on GitHub: Pull Request from your branch into `develop`, ask one teammate to review, then merge.

## Why merging will be easy
- Each person edits different folders and different files, so Git has nothing to conflict on.
- The only shared files are `README.md`, `requirements.txt`, `docs/interfaces.md` and `frontend/app.py`.
  Change those in a small separate pull request and tell the group.
- Commit messages start with the component: `c1:`, `c2:`, `c3:`, `c4:`.

## Standards
- Python 3.11, formatted with `black`, imports at the top.
- Paths: use `Path(__file__).resolve().parents[N]` from your own folder; never `D:\...` paths.
- Every function that produces a number documents its source or rule (the project's evidence rule).
- Each component has its own `README.md` stating inputs, outputs, how to run and how to test.
