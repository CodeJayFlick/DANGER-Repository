import bert_model
import roberta_model

bert_models_to_train : list[str] = ["bert-base-cased", "bert-base-uncased"]
roberta_models_to_train : list[str] = ["roberta-base"]
num_epochs = 20

for bert_model_name in bert_models_to_train:
    bert_model.model_name = bert_model_name
    bert_model.model_save_path = f"{bert_model_name.replace('/', '_ _')}_finetuned.pth" 
    bert_model.num_epochs = num_epochs
    bert_model.main()

for roberta_model_name in roberta_models_to_train:
    roberta_model.model_name = roberta_model_name
    roberta_model.model_save_path = f"{roberta_model_name.replace('/', '_ _')}_finetuned.pth" 
    bert_model.num_epochs = num_epochs
    roberta_model.main()
