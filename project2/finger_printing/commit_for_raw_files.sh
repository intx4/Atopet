ls ./raw | xargs sh -c 'for arg do git add $./raw/arg/.; git commit -m "raw cell update $arg"; git push;done'
