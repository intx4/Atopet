ls ./filtered | xargs sh -c 'for arg do git reset filtered/$arg/.; done'
ls ./filtered | xargs sh -c 'for arg do git add filtered/$arg/.; git commit -m "added filtered $arg";git push origin part3; done'
