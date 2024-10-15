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


# load data below

df = pd.read_csv('https://raw.githubusercontent.com/kenneth-lee-ch/SMS-Spam-Classification/master/spam.csv', encoding='ISO-8859-1')
# rename the columns
df = df[['v1','v2']]
df.rename(columns={'v1':'label', 'v2':'message'}, inplace=True)
print(df.head())
print(df.describe())

#------------

ham_msg_text = " ".join(list(df[df['label'] == 'ham']['message']))
print(ham_msg_text)
ham_msg_cloud = WordCloud(width =520, height =260, stopwords = STOPWORDS, max_font_size = 50, background_color = "black", colormap = 'Pastel1').generate(ham_msg_text)
plt.figure(figsize=(16,10))
plt.imshow(ham_msg_cloud, interpolation = 'bilinear')
plt.axis('off') # turn off axis
plt.show()

#------ 

plt.figure(figsize=(8,6))
sns.countplot(df.label)
plt.title('The distribution of ham and spam messages')
plt.show()

#-----

