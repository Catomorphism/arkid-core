'''
create mock company for dev
'''
import django
from oneid_meta.models import Dept
from djangosaml2idp.scripts import idpinit

django.setup()


def create_top_company():
    '''创建公司初始信息
    '''
    root = Dept.objects.get(uid='root')
    if not Dept.valid_objects.filter(parent=root).exists():
        print("create top company")
        Dept.valid_objects.create(uid='company', name='公司', parent=root)


def main():
    '''
    :note: 所有方法需保证幂等
    '''
    create_top_company()
    idpinit.run()


if __name__ == "__main__":
    main()
