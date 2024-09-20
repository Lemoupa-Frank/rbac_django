# Django Project: [rbac_django]

rbac is project that demonstrates basic RBAC using Django Rest Framework.

## Installation

clone the repository

```bash
git clone https://github.com/Lemoupa-Frank/rbac_django.git
cd rbac_django
```


Create a virtual enviroment inside project.
```bash
python -m venv venv
source venv/bin/activate
```

install django and django restframework.
```bash  
python -m pip install Django
python -m pip install djangorestframework
```
Migrate and create superuser go to localhost
```bash  
python manage.py migrate
python group.py
python manage.py createsuperuser 
``` 
## Usage
Only the super can create all types of users other 
users are employer(which can create client) and client 

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)