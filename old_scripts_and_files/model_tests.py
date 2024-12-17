# sample source https://nzlul.medium.com/the-classification-of-text-messages-using-lstm-bi-lstm-and-gru-f79b207f90ad

# Load, explore and plot data
import numpy as np
import pandas as pd
import seaborn as sns
print("here 1")
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS, ImageColorGenerator
# %matplotlib inline
# Train test split
from sklearn.model_selection import train_test_split
print("here 2")
# Text pre-processing
import tensorflow as tf

from keras_preprocessing.text import Tokenizer
from keras_preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping # type: ignore # for some reason, this import is not recognized but it does exist
from keras.callbacks import EarlyStopping # type: ignore # for some reason, this import is not recognized but it does exist
# Modeling
from keras.models import Sequential # type: ignore # for some reason, this import is not recognized but it does exist
from keras.layers import LSTM, GRU, Dense, Embedding, Dropout, GlobalAveragePooling1D, Flatten, SpatialDropout1D, Bidirectional # type: ignore # for some reason, this import is not recognized but it does exist


DO_DATA_FIGURE = False
DO_DIST_COUNT = False

# load data below

df = pd.read_csv('https://raw.githubusercontent.com/kenneth-lee-ch/SMS-Spam-Classification/master/spam.csv', encoding='ISO-8859-1')
# rename the columns
df = df[['v1','v2']]
df.rename(columns={'v1':'label', 'v2':'message'}, inplace=True)
print(df.head())
print(df.describe())

#------------

if DO_DATA_FIGURE:
    ham_msg_text = " ".join(list(df[df['label'] == 'ham']['message']))
    print(ham_msg_text)
    ham_msg_cloud = WordCloud(width =520, height =260, stopwords = STOPWORDS, max_font_size = 50, background_color = "black", colormap = 'Pastel1').generate(ham_msg_text)
    plt.figure(figsize=(16,10))
    plt.imshow(ham_msg_cloud, interpolation = 'bilinear')
    plt.axis('off') # turn off axis
    plt.show()

#------ 

if DO_DIST_COUNT:
    plt.figure(figsize=(8,6))
    sns.countplot(df.label)
    plt.title('The distribution of ham and spam messages')
    plt.show()

#-----


df['text_length'] = df['message'].apply(len)

df['msg_type'] = df['label'].map({'ham':0, 'spam':1})
msg_label = df['msg_type'].values
print(df.head())

x_train, x_test, y_train, y_test = train_test_split(df['message'], msg_label, test_size=0.2, random_state=434)


# Defining pre-processing parameters
max_len = 50
trunc_type = 'post'
padding_type = 'post'
oov_tok = '<OOV>' # out of vocabulary token
vocab_size = 500


tokenizer = Tokenizer(num_words = vocab_size, 
                      char_level = False,
                      oov_token = oov_tok)
tokenizer.fit_on_texts(x_train)

# Get the word_index
word_index = tokenizer.word_index
total_words = len(word_index)
print(total_words)

training_sequences = tokenizer.texts_to_sequences(x_train)
training_padded = pad_sequences(training_sequences,
                                #maxlen = max_len,
                                padding = padding_type,
                                truncating = trunc_type)

testing_sequences = tokenizer.texts_to_sequences(x_test)
testing_padded = pad_sequences(testing_sequences,
                               maxlen = max_len,
                               padding = padding_type,
                               truncating = trunc_type)

print('Shape of training tensor: ', training_padded.shape)
print('Shape of testing tensor: ', testing_padded.shape)

# Define parameter
vocab_size = 500 
embedding_dim = 16
drop_value = 0.2
n_dense = 24
# Define Dense Model Architecture
model = Sequential()
model.add(Embedding(vocab_size,
                    embedding_dim))
model.add(GlobalAveragePooling1D())
model.add(Dense(24, activation='relu'))
model.add(Dropout(drop_value))
model.add(Dense(1, activation='sigmoid'))

model.summary()

model.compile(loss = 'binary_crossentropy', optimizer = 'adam' , metrics = ['accuracy'])

num_epochs = 30
early_stop = EarlyStopping(monitor='val_loss', patience=10000)
history = model.fit(training_padded,
                    y_train,
                    epochs=num_epochs, 
                    validation_data=(testing_padded, y_test),
                    callbacks =[early_stop],
                    verbose=2)

model.evaluate(testing_padded, y_test)
