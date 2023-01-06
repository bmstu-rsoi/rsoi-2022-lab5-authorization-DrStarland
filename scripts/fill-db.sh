# postgresPod=$1
postgresPod=$(kubectl get pods -l app=postgres -o=jsonpath='{.items[].metadata}' | jq -r '.name')

cat postgres/dumps/flights.dump.sql           | kubectl exec -i $postgresPod -- psql -U program flights
cat postgres/dumps/privileges.dump.sql        | kubectl exec -i $postgresPod -- psql -U program privileges
cat postgres/dumps/tickets.dump.sql           | kubectl exec -i $postgresPod -- psql -U program tickets 