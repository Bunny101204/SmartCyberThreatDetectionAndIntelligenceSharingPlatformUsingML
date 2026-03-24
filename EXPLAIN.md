# ML-Based Cyber Threat Detection and Selective Threat Intelligence Sharing Platform (MISP-Inspired)

## Objective
This project builds a simulated cyber threat detection system using machine learning models to classify network traffic as normal or various types of attacks. It includes a selective sharing mechanism inspired by MISP (Malware Information Sharing Platform) where detected threats can be shared within predefined groups, allowing collaborative defense among trusted nodes.

## ML Models Used
The system employs four machine learning models for threat detection:
- **Random Forest**: An ensemble method using multiple decision trees for robust classification.
- **XGBoost**: A gradient boosting algorithm known for high performance in classification tasks.
- **Support Vector Machine (SVM)**: Effective for binary and multi-class classification with kernel tricks.
- **Decision Tree**: A simple, interpretable model that splits data based on feature values.

## Ensemble Concept
The system uses a majority voting ensemble method where each model predicts the traffic class, and the final prediction is the most voted class. This approach combines the strengths of different models to improve accuracy and reduce overfitting.

## What is IOC
IOC stands for Indicator of Compromise. In cybersecurity, IOCs are artifacts observed on a network or in an operating system that indicate a potential security breach. Examples include suspicious IP addresses, file hashes, or unusual network patterns. In this project, detected attack traffic serves as IOCs that can be shared.

## How Sharing Works
The platform simulates multiple laptops grouped into two teams (Group A: Laptop1, Laptop2; Group B: Laptop3, Laptop4). When a threat is detected, it can be shared to the group. Only members of the same group can access shared threats, ensuring selective intelligence sharing. Data is stored in JSON files for simplicity.

## Relation to MISP
MISP is an open-source threat intelligence platform that facilitates the sharing of IOCs and threat information among organizations. This project is inspired by MISP's concept of collaborative threat sharing but simplified for demonstration. It implements group-based access control similar to MISP's sharing groups, allowing trusted entities to exchange threat intelligence while maintaining privacy.

## Limitations
- Uses simulated network traffic instead of real-time packet capture.
- Limited to NSL-KDD dataset features; may not generalize to all modern threats.
- Simple JSON storage instead of a robust database.
- No authentication or encryption for shared data.
- Ensemble voting may not always outperform individual models in all scenarios.

## Future Improvements
- Integrate real-time packet capture using libraries like Scapy.
- Expand to more datasets and modern threat types.
- Implement a full database (e.g., PostgreSQL) with proper indexing.
- Add user authentication and role-based access control.
- Enhance MISP integration with actual API calls for event creation.
- Include more advanced ensemble methods like weighted voting or stacking.
- Add visualization dashboards with charts and graphs.
- Implement automated threat response actions.