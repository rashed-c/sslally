from django.shortcuts import render
from ratelimit.decorators import ratelimit
import psycopg2


@ratelimit(key='ip', rate='1/m')
def home(request):
    conn = psycopg2.connect("host=sslally-db.crdjigjiw9yx.us-east-1.rds.amazonaws.com",
    dbname="postgres",
    user="dbmaster", 
    password="G55AwhDzsHY2NouhPFnL")
    cur = conn.cursor()
    print('PostgreSQL database version:')
    cur.execute('SELECT version()')
        # display the PostgreSQL database server version
    db_version = cur.fetchone()
    print(db_version)
    context = {
        "db_version" : db_version
    }
       
    return render(request, 'polls/sslmonitor.html', context)
