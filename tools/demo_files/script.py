import random

# field = ''
# for i in range(128):
#     num = ''
#     for j in range(8):
#         num = num + random.choice('1234567890')
#     field = field + 'user' + str(i) + ' ' + num + '\n'
# print(field)
field = ''
for i in range(128):
    field = field + '/home/vagrant/MES/tools/demo_files/2048 2048 1.' + i  + 'user1 user0 demo user30\n'

f = open('alex_test_games.txt', 'w')
f.write(field)
f.close()