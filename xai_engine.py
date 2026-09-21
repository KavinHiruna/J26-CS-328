import numpy as np
import pandas as pd
import shap
from lime.lime_tabular import LimeTabularExplainer


class XAIEngine:
    """SHAP + LIME explanation layer for a trained tabular IDS model."""

    def __init__(self, model, X_train, feature_names, class_names):
        self.model = model
        self.X_train = np.asarray(X_train)
        self.feature_names = list(feature_names)
        self.class_names = list(class_names)

        # TreeExplainer is suitable for tree-based models such as Random Forest.
        self.shap_explainer = shap.TreeExplainer(model)

        self.lime_explainer = LimeTabularExplainer(
            self.X_train,
            feature_names=self.feature_names,
            class_names=self.class_names,
            mode="classification",
            discretize_continuous=True,
            random_state=42,
        )

    def predict(self, row):
        """Return predicted class and probability."""
        row = pd.DataFrame(
            [np.asarray(row).reshape(-1)],
            columns=self.feature_names
        )
        pred = int(self.model.predict(row)[0])
        probs = self.model.predict_proba(row)[0]
        return pred, probs

    def shap_explanation(self, row, class_index=None):
        """
        Return SHAP values for one observation.

        The method handles SHAP's different output formats across versions.
        """
        row = np.asarray(row).reshape(1, -1)
        pred, probs = self.predict(row)

        values = self.shap_explainer.shap_values(row)

        if isinstance(values, list):
            # Older/common TreeExplainer format:
            # [class_0_values, class_1_values, ...]
            idx = pred if class_index is None else class_index
            shap_values = np.asarray(values[idx])[0]
        else:
            values = np.asarray(values)

            # Possible shapes:
            # (samples, features, classes)
            # (samples, classes, features)
            # (samples, features)
            if values.ndim == 3:
                if values.shape[1] == len(self.feature_names):
                    shap_values = values[0, :, pred]
                else:
                    shap_values = values[0, pred, :]
            elif values.ndim == 2:
                shap_values = values[0]
            else:
                shap_values = values.reshape(-1)

        return {
            "prediction": pred,
            "probabilities": probs,
            "shap_values": np.asarray(shap_values, dtype=float),
        }

    def lime_explanation(self, row, num_features=8):
        """Return local LIME feature contributions for one observation."""
        row = np.asarray(row).reshape(-1)

        pred, probs = self.predict(row)

        exp = self.lime_explainer.explain_instance(
            row,
            self.model.predict_proba,
            num_features=min(num_features, len(self.feature_names)),
            top_labels=1,
        )

        pairs = exp.as_list(label=pred)
        return {
            "prediction": pred,
            "probabilities": probs,
            "features": pairs,
            "score": exp.score,
        }

    def feature_ranking(self, X):
        """Global mean absolute SHAP feature importance."""
        X = np.asarray(X)
        values = self.shap_explainer.shap_values(X)

        if isinstance(values, list):
            arr = np.stack([np.asarray(v) for v in values], axis=-1)
            # samples x features x classes
            importance = np.mean(np.abs(arr), axis=(0, 2))
        else:
            arr = np.asarray(values)
            if arr.ndim == 3:
                if arr.shape[1] == len(self.feature_names):
                    importance = np.mean(np.abs(arr), axis=(0, 2))
                else:
                    importance = np.mean(np.abs(arr), axis=(0, 1))
            else:
                importance = np.mean(np.abs(arr), axis=0)

        return (
            pd.DataFrame(
                {"feature": self.feature_names, "importance": importance}
            )
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )

    def human_readable_explanation(
        self,
        row,
        shap_result,
        feature_labels=None,
        top_n=4,
    ):
        """
        Convert SHAP contributions into analyst-friendly sentences.

        Positive contribution means the feature pushes the prediction toward
        the predicted class; negative contribution pushes away from it.
        """
        pred = shap_result["prediction"]
        probs = shap_result["probabilities"]
        values = shap_result["shap_values"]

        label = self.class_names[pred]
        confidence = float(probs[pred])

        df = pd.DataFrame(
            {
                "feature": self.feature_names,
                "value": np.asarray(row).reshape(-1),
                "shap": values,
            }
        )
        df["abs_shap"] = df["shap"].abs()
        top = df.sort_values("abs_shap", ascending=False).head(top_n)

        if feature_labels is None:
            feature_labels = {}

        lines = [
            f"Prediction: {label}",
            f"Confidence: {confidence:.1%}",
            "Main reasons:"
        ]

        for _, item in top.iterrows():
            direction = "supports" if item["shap"] >= 0 else "opposes"
            display_name = feature_labels.get(item["feature"], item["feature"])
            lines.append(
                f"- {display_name} = {item['value']:.3f} "
                f"{direction} the {label} prediction."
            )

        return "\n".join(lines)
