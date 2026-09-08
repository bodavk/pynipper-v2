class Issue:

    def __init__(self, title, observation, impact, ease, recommendation):
        self.title = title
        self.observation = observation
        self.impact = impact
        self.ease = ease
        self.recommendation = recommendation

    def __str__(self):
        result = f"Issue {self.title}:\n"
        result += "=" * 100 + "\n"
        result += f"Observation: {self.observation}\n"
        result += f"Impact: {self.impact}\n"
        result += f"Ease: {self.ease}\n"
        result += f"Recommendation: {self.recommendation}\n"
        result += "-" * 100 + "\n"
        return result

    def to_dict(self):
        return {
            'title': self.title,
            'observation': self.observation,
            'impact': self.impact,
            'ease': self.ease,
            'recommendation': self.recommendation
        }
