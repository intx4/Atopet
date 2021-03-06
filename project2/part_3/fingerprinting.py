import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, RepeatedStratifiedKFold
from sklearn.model_selection import cross_val_score
from sklearn import metrics
import pandas as pd
import sys


def classify(train_features, train_labels, test_features):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = RepeatedStratifiedKFold(n_splits=folds, n_repeats=10)
    labels = np.array(labels)
    features = np.array(features)
    exact_matches = []
    
    epoch = 0
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test)


        exact_match = 0
        for prediction, true in zip(predictions, y_test):
            if prediction == true:
                exact_match += 1
        
        exact_matches.append(exact_match/len(y_test))
        
        epoch += 1
        print(f"Exact match ratio epoch {epoch}: {exact_match/len(y_test)}")
        
    exact_matches = np.array(exact_matches)
    print(f"Avg Exact match ratio: {exact_matches.mean()}. Std: {exact_matches.std()}")

def cross_validator(features, labels):
    clf = RandomForestClassifier()
    cv = RepeatedStratifiedKFold(n_splits=10, n_repeats=5)
    scores = cross_val_score(clf, features, labels, cv=cv)
    print(f"Avg Exact match ratio: {scores.mean()}. Std: {scores.std()}")
    with open('classifier_score.txt', 'w') as f:
        f.write(f"Avg Exact match ratio: {scores.mean()}. Std: {scores.std()}. Entries {len(labels)}. Epochs: {50}")
    
def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    ###############################################
    features = []
    
    features_df = pd.read_csv('./finger_printing/features.csv').to_numpy()
    
    for row in features_df:
        labels.append(int(row[0]))
        features.append(row[1:])

    return labels, features
        
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    labels, features = load_data()
    #perform_crossval(features, labels, folds=10)
    cross_validator(features, labels)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)